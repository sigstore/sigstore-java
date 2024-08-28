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
package dev.sigstore.sign

import dev.sigstore.sign.tasks.SigstoreSignFilesTask
import org.gradle.api.Action
import org.gradle.api.DefaultTask
import org.gradle.api.DomainObjectCollection
import org.gradle.api.Project
import org.gradle.api.plugins.ExtensionAware
import org.gradle.api.provider.Property
import org.gradle.api.publish.Publication
import org.gradle.api.publish.PublicationArtifact
import org.gradle.api.publish.internal.PublicationInternal
import org.gradle.api.publish.maven.MavenArtifact
import org.gradle.api.publish.maven.internal.artifact.AbstractMavenArtifact
import org.gradle.api.publish.maven.internal.artifact.DerivedMavenArtifact
import org.gradle.kotlin.dsl.create
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.the
import org.gradle.kotlin.dsl.withType
import org.gradle.plugins.signing.Sign
import kotlin.collections.set

abstract class SigstoreSignExtension(private val project: Project) {
    private val Publication.signingTaskName: String
        get() = "sigstoreSign${name.titlecase()}Publication"

    abstract val sigstoreJavaVersion : Property<String>

    init {
        sigstoreJavaVersion.convention("1.1.0")
        (this as ExtensionAware).extensions.create<OidcClientExtension>(
            "oidcClient",
            project.objects,
        )
    }

    fun sign(publications: DomainObjectCollection<Publication>) {
        publications.all {
            sign(this)
        }
        publications.whenObjectRemoved {
            project.tasks.named(signingTaskName) {
                enabled = false
            }
        }
    }

    fun sign(vararg publications: Publication) {
        for (publication in publications) {
            sign(publication as PublicationInternal<*>)
        }
    }

    val oidcClient: OidcClientExtension
        get() = (this as ExtensionAware).the()

    fun oidcClient(configure: Action<OidcClientExtension>) {
        configure.execute((this as ExtensionAware).the())
    }

    private fun <T : PublicationArtifact> sign(publication: PublicationInternal<T>) {
        val taskName = publication.signingTaskName
        val signatureDirectory = project.layout.buildDirectory.dir("sigstore/$taskName")
        val signTask = project.tasks.register<SigstoreSignFilesTask>(taskName) {
            description = "Sign all artifacts in ${publication.name} publication in Sigstore"
            this.signatureDirectory.set(signatureDirectory)
        }

        val removeSigstoreAsc =
            project.findProperty("dev.sigstore.sign.remove.sigstore.json.asc")?.toString()?.toBoolean() != false

        val publicationName = publication.name

        val artifacts = mutableMapOf<PublicationArtifact, T>()
        publication.allPublishableArtifacts {
            val publishableArtifact = this
            if (!file.name.endsWith(".asc") && !file.name.endsWith(SigstoreSignature.DOT_EXTENSION)) {
                val signatureLocation =
                    signatureDirectory.map { it.file(file.name + SigstoreSignature.DOT_EXTENSION) }
                signTask.configure {
                    sign(publishableArtifact.file, builtBy = publishableArtifact)
                        .outputSignature.set(signatureLocation)
                }
                val dervied = DefaultDerivedArtifactFile(project.tasks.named<DefaultTask>(signTask.name), signatureLocation)
                artifacts[publishableArtifact] = publication.addDerivedArtifact(publishableArtifact, dervied).apply {
                    builtBy(signTask)
                    // TODO: workaround for https://github.com/gradle/gradle/issues/28969
                    // TODO: Behavior is undefined for non-maven artifacts.
                    if (publishableArtifact is AbstractMavenArtifact) {
                        (this as DerivedMavenArtifact).setExtension((publishableArtifact as AbstractMavenArtifact).extension + SigstoreSignature.DOT_EXTENSION)
                    }
                }
                // Gradle's signing plugin reacts on adding artifacts, and it might add .asc signature
                // So we need to remove .sigstore.json.asc as it is unwanted in most of the cases
                if (removeSigstoreAsc) {
                    project.tasks.withType<Sign>()
                        .matching { it.name.contains(publicationName, ignoreCase = true) }
                        .configureEach {
                            // Remove .sigstore.json.asc signature.
                            // Unfortunately, it will scan all the signatures every time,
                            // however, it seems to be the only way to do it since the artifacts can be added
                            // within afterEvaluate block, so we can't use afterEvaluate
                            // to "remove all .sigstore.json.asc" at once
                            signatures.removeIf { it.name.endsWith(SigstoreSignature.DOT_EXTENSION + ".asc") }
                            signatures.removeIf { it.name.endsWith(".sigstore.asc") }
                        }
                }
            }
        }
        publication.whenPublishableArtifactRemoved {
            val publishableArtifact = this
            // Ignore artifacts that we have not added a signature for
            val artifact = artifacts.remove(publishableArtifact) ?: return@whenPublishableArtifactRemoved
            signTask.configure {
                signatures.findByName(publishableArtifact.file.name)
                    ?.takeIf { publishableArtifact in it.builtBy }
                    ?.let {
                        signatures.remove(it)
                        return@configure
                    }
                // Slow path just in case
                signatures.removeIf { publishableArtifact in it.builtBy }
            }
            publication.removeDerivedArtifact(artifact)
        }
    }
}
