/*
 * Copyright 2022 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package dev.sigstore.sign.tasks

import dev.sigstore.sign.SigstoreSignExtension
import dev.sigstore.sign.SigstoreSignature
import dev.sigstore.sign.services.SigstoreSigningService
import dev.sigstore.sign.work.SignWorkAction
import org.gradle.api.Buildable
import org.gradle.api.DefaultTask
import org.gradle.api.JavaVersion
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.file.*
import org.gradle.api.model.ObjectFactory
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.provider.ProviderFactory
import org.gradle.api.tasks.*
import org.gradle.jvm.toolchain.JavaLauncher
import org.gradle.jvm.toolchain.JavaToolchainService
import org.gradle.kotlin.dsl.findByType
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.the
import org.gradle.work.DisableCachingByDefault
import org.gradle.workers.WorkerExecutor
import java.io.File
import javax.inject.Inject

@DisableCachingByDefault(because = "Sigstore signatures are true-timestamp dependent, so we should not cache signatures")
abstract class SigstoreSignFilesTask : DefaultTask() {
    companion object {
        private val PROPERTY_SET_PROVIDER = Property::class.java.getMethod("set", Provider::class.java)
    }

    init {
        @Suppress("UNCHECKED_CAST")
        val service: Provider<SigstoreSigningService> =
            project.gradle.sharedServices.registrations[SigstoreSigningService.SERVICE_NAME].service as Provider<SigstoreSigningService>

        // Use reflection to resolve set(Provider) vs set(Object) ambiguity
        @Suppress("LeakingThis")
        PROPERTY_SET_PROVIDER.invoke(signingService, service)
        // See https://docs.gradle.org/current/userguide/build_services.html
        @Suppress("LeakingThis")
        usesService(service)
    }

    /**
     * Signing service is there so none of the signing tasks execute concurrently.
     * It reduces the number of OIDC flows, and it makes throttling Fulcio and Rekor requests easier.
     *
     * Type is `Any` to workaround https://github.com/gradle/gradle/issues/17559
     */
    @get:Internal
    protected abstract val signingService: Property<Any>

    @Nested
    val signatures: NamedDomainObjectContainer<SigstoreSignature> =
        objects.domainObjectContainer(SigstoreSignature::class.java) {
            objects.newInstance(
                SigstoreSignature::class.java,
                it,
            )
        }

    @get:Classpath
    @get:InputFiles
    protected abstract val sigstoreClientClasspath: ConfigurableFileCollection

    @get:Internal
    abstract val signatureDirectory: DirectoryProperty

    @get:Nested
    @get:Optional
    abstract val launcher: Property<JavaLauncher>

    @get:Inject
    protected abstract val workerExecutor: WorkerExecutor

    @get:Inject
    protected abstract val providers: ProviderFactory

    @get:Inject
    protected abstract val objects: ObjectFactory

    @get:Inject
    protected abstract val layout: ProjectLayout

    init {
        outputs.upToDateWhen {
            // Sigstore signatures are true-timestamp dependent, so we should not cache signatures
            false
        }
        outputs.cacheIf("Sigstore signatures are true-timestamp dependent, so we should not cache signatures") {
            false
        }
        sigstoreClientClasspath.from(project.configurations["sigstoreClientClasspath"])
        signatureDirectory.convention(
            layout.buildDirectory.dir("sigstore/$name")
        )

        project.extensions.findByType<JavaPluginExtension>()?.let { java ->
            launcher.convention(
                project.the<JavaToolchainService>()
                    .launcherFor(java.toolchain)
            )
        }
    }

    /**
     * Signs a given [File] in Sigstore.
     */
    @JvmOverloads
    fun sign(file: File, builtBy: Buildable? = null): SigstoreSignature =
        sign(layout.file(providers.provider { file }), builtBy = builtBy)

    /**
     * Signs a given [Provider<File>] in Sigstore. The method name is different from [sign] to resolve ambiguity
     * between [Provider<File>] and [Provider<RegularFile>]
     */
    @JvmOverloads
    fun signFile(fileProvider: Provider<File>, builtBy: Buildable? = null): SigstoreSignature =
        sign(layout.file(fileProvider), builtBy = builtBy)

    /**
     * Signs a given [Provider<RegularFile>].
     */
    @JvmOverloads
    fun sign(file: Provider<RegularFile>, builtBy: Buildable? = null): SigstoreSignature =
        signatures.create(file.get().asFile.name) {
            this.file.setFrom(file)
            builtBy?.let { builtBy(it) }
            this.signatureDirectory.convention(this@SigstoreSignFilesTask.signatureDirectory)
        }

    /**
     * Retrieves a single signature when only one file was registered for the signing task.
     */
    fun singleSignature(): RegularFileProperty =
        signatures.single().outputSignature

    @TaskAction
    protected fun sign() {
        // Ensure task holds a lock, so no other signign tasks executes concurrently
        signingService.get()
        val javaLauncher = launcher.orNull
        if (javaLauncher != null) {
            val javaVersion = javaLauncher.metadata.languageVersion.asInt()
            if (javaVersion < 11) {
                throw IllegalArgumentException(
                    "Java 11 or higher is required to run Sigstore client. " +
                            "Got Java $javaVersion (${javaLauncher.metadata.installationPath}). " +
                            "Please use Java 11 or newer to launch Gradle or configure toolchain for ${SigstoreSignFilesTask::class.qualifiedName} tasks."
                )
            }
        } else if (!JavaVersion.current().isJava11Compatible) {
            throw IllegalArgumentException(
                "Java 11 or higher is required to run Sigstore client. " +
                        "The current Java is ${JavaVersion.current()}. " +
                        " Please use Java 11 or newer to launch Gradle or configure toolchain for ${SigstoreSignFilesTask::class.qualifiedName} tasks."
            )
        }
        workerExecutor
            .processIsolation {
                classpath.from(sigstoreClientClasspath)
                forkOptions {
                    javaLauncher?.executablePath?.let { executable(it) }
                    // TODO: we pass the whole env to the fork, but maybe in the future an allow list makes sense.
                    environment(System.getenv())
                }
            }
            .run {
                for (signature in signatures) {
                    val file = signature.file.singleFile
                    if (!file.exists()) {
                        continue
                    }
                    logger.lifecycle("Signing $file via Sigstore")
                    submit(SignWorkAction::class.java) {
                        inputFile.set(file)
                        outputSignature.set(signature.outputSignature)
                    }
                    // Wait after submitting each action, so the worker become active, and we can reuse it.
                    // It enables reusing Fulcio certificates
                    await()
                }
            }
    }
}
