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
import org.gradle.kotlin.dsl.create
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.the
import kotlin.collections.set

abstract class SigstoreSignExtension(private val project: Project) {
    private val Publication.signingTaskName: String
        get() = "sigstoreSign${name.titlecase()}Publication"

    abstract val sigstoreJavaVersion : Property<String>

    init {
        sigstoreJavaVersion.convention("0.2.0")
        (this as ExtensionAware).extensions.create<OidcClientExtension>(
            "oidcClient",
            project.objects,
        )
    }

    fun sign(publications: DomainObjectCollection<Publication>) {
        publications.all {
            project.logger.lifecycle("Signing $this")
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

        val artifacts = mutableMapOf<PublicationArtifact, T>()
        publication.allPublishableArtifacts {
            val publishableArtifact = this
            if (file.extension !in listOf("asc", SigstoreSignature.EXTENSION)) {
                val signatureLocation =
                    signatureDirectory.map { it.file(file.name + "." + SigstoreSignature.EXTENSION) }
                signTask.configure {
                    sign(publishableArtifact.file, builtBy = publishableArtifact)
                        .outputSignature.set(signatureLocation)
                }
                artifacts[publishableArtifact] = publication.addDerivedArtifact(
                    publishableArtifact,
                    DefaultDerivedArtifactFile(project.tasks.named<DefaultTask>(signTask.name), signatureLocation)
                ).apply { builtBy(signTask) }
            }
        }
        publication.whenPublishableArtifactRemoved {
            val publishableArtifact = this
            signTask.configure {
                signatures.findByName(file.name)
                    ?.takeIf { publishableArtifact in it.builtBy  }
                    ?.let {
                        signatures.remove(it)
                        return@configure
                    }
                // Slow path just in case
                signatures.removeIf { publishableArtifact in it.builtBy }
            }
            val artifact = artifacts.remove(publishableArtifact)
            publication.removeDerivedArtifact(artifact)
        }
    }
}
