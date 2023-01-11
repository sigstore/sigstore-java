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

import dev.sigstore.sign.OidcClientConfiguration
import dev.sigstore.sign.SigstoreSignExtension
import dev.sigstore.sign.SigstoreSignature
import dev.sigstore.sign.work.SignWorkAction
import org.gradle.api.Buildable
import org.gradle.api.DefaultTask
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.file.*
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.provider.ProviderFactory
import org.gradle.api.tasks.*
import org.gradle.kotlin.dsl.get
import org.gradle.kotlin.dsl.the
import org.gradle.work.DisableCachingByDefault
import org.gradle.workers.WorkerExecutor
import java.io.File
import javax.inject.Inject

@DisableCachingByDefault(because = "Sigstore signatures are true-timestamp dependent, so we should not cache signatures")
abstract class SigstoreSignFilesTask : DefaultTask() {
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

    @get:Internal
    abstract val oidcClient: Property<OidcClientConfiguration>

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
        oidcClient.convention(
            project.the<SigstoreSignExtension>().oidcClient.client
        )
        signatureDirectory.convention(
            layout.buildDirectory.dir("sigstore/$name")
        )
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
            this.file.set(file)
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
        workerExecutor
            .processIsolation {
                classpath.from(sigstoreClientClasspath)
                forkOptions {
                    environment(System.getenv())
                }
            }
            .run {
                for (signature in signatures) {
                    submit(SignWorkAction::class.java) {
                        inputFile.set(signature.file)
                        outputSignature.set(signature.outputSignature)
                        oidcClient.set(this@SigstoreSignFilesTask.oidcClient.get())
                    }
                }
                await()
            }
    }
}
