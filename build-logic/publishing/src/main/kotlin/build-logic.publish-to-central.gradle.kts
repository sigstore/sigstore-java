import org.gradle.api.publish.internal.PublicationInternal

plugins {
    id("java-library")
    id("maven-publish")
}

val repoUrl = "https://github.com/sigstore/sigstore-java"

publishing {
    publications.withType<MavenPublication>().configureEach {
        // Use the resolved versions in pom.xml
        // Gradle might have different resolution rules, so we set the versions
        // that were used in Gradle build/test.
        versionMapping {
            usage(Usage.JAVA_RUNTIME) {
                fromResolutionResult()
            }
            usage(Usage.JAVA_API) {
                fromResolutionOf("runtimeClasspath")
            }
        }
        pom {
            name.set(
                (project.findProperty("artifact.name") as? String)
                    ?: project.name
            )
            // This code might be executed before project-related build.gradle.kts is evaluated
            // So we delay access to project.description
            description.set(
                project.provider { project.description }
            )
            inceptionYear.set("2022")
            url.set(repoUrl)
            organization {
                name.set("Sigstore")
                url.set("https://sigstore.dev")
            }
            developers {
                developer {
                    organization.set("Sigstore authors")
                    organizationUrl.set("https://sigstore.dev")
                }
            }
            issueManagement {
                system.set("GitHub Issues")
                url.set("$repoUrl/issues")
            }
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
            scm {
                connection.set("scm:git:$repoUrl.git")
                developerConnection.set("scm:git:$repoUrl.git")
                url.set(repoUrl)
                tag.set("HEAD")
            }
        }
    }
}

val createReleaseBundle by tasks.registering(Sync::class) {
    description = "This task should be used by github actions to create release artifacts along with a slsa attestation"
    val releaseDir = layout.buildDirectory.dir("release")
    outputs.dir(releaseDir)

    into(releaseDir)
    rename("pom-default.xml", "${project.name}-${project.version}.pom")
    rename("module.json", "${project.name}-${project.version}.module")
}

publishing {
    publications.configureEach {
        (this as PublicationInternal<*>).allPublishableArtifacts {
            val publicationArtifact = this
            createReleaseBundle.configure {
                dependsOn(publicationArtifact)
                from(publicationArtifact.file)
            }
        }
    }
}

