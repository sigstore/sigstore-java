import org.codehaus.groovy.runtime.StringGroovyMethods
import org.gradle.api.publish.internal.PublicationInternal
import org.gradle.api.publish.internal.PublicationInternal.DerivedArtifact
import org.gradle.api.publish.maven.internal.publication.MavenPublicationInternal

plugins {
    id("build-logic.repositories")
    id("build-logic.java-library")
    id("build-logic.reproducible-builds")
    id("build-logic.publish-to-central")
    id("build-logic.signing")
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}

createSignTask(publishing.publications["mavenJava"])

fun createSignTask(publicationToSign: Publication) {
    val signTaskName = "sign" + StringGroovyMethods.capitalize(publicationToSign.name) + "Publication"
    if (project.tasks.names.contains(signTaskName)) {
        throw GradleException("can't create custom sign task (it already exists): $signTaskName")
    } else {
        project.tasks.create<Sign>(signTaskName) { // must be create (not register)
            val task = this
            task.description = "Signs all artifacts in the 'mavenJava' publication."
            if (publicationToSign !is MavenPublicationInternal) {
                throw GradleException("can't configure signing for non-MavenPublication")
            }
            publicationToSign.allPublishableArtifacts {
                if (task.signatureFiles.contains(this.file) || this.file.name.endsWith(".sigstore")) { // or .sigstore.json eventually
                    return@allPublishableArtifacts
                }
                task.dependsOn(this)
                val signature = Signature(this::getFile, null, task as SignatureSpec, this)
                task.signatures.add(signature)
                val derivedArtifact = object : DerivedArtifact {
                    override fun shouldBePublished(): Boolean {
                        return task.isEnabled && task.onlyIf.isSatisfiedBy(task)
                    }

                    override fun create(): File {
                        return signature.file
                    }
                }
                publicationToSign.addDerivedArtifact(this, derivedArtifact)
            }
        }
    }
}
