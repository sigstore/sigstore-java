import org.gradle.api.attributes.Bundling
import org.gradle.api.attributes.Category
import org.gradle.kotlin.dsl.*
import java.io.File

plugins {
    java
}

val sigstoreMavenPluginRuntime by configurations.creating {
    description = "declares dependencies that will be useful for testing purposes"
    isCanBeConsumed = false
    isCanBeResolved = false
}

val sigstoreMavenPluginTestClasspath by configurations.creating {
    description = "sigstore-maven-plugin in local repository for testing purposes"
    isCanBeConsumed = false
    isCanBeResolved = true
    extendsFrom(sigstoreMavenPluginRuntime)
    attributes {
        attribute(Category.CATEGORY_ATTRIBUTE, objects.named("maven-repository"))
        attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
    }
}

tasks.test {
    dependsOn(sigstoreMavenPluginTestClasspath)
    systemProperty("sigstore.test.current.maven.plugin.version", version)
    val projectDir = layout.projectDirectory.asFile
    // This adds paths to the local repositories that contain currently-built sigstore-maven-plugin
    jvmArgumentProviders.add(
        // Gradle does not support Provider for systemProperties yet, see https://github.com/gradle/gradle/issues/12247
        CommandLineArgumentProvider {
            listOf(
                "-Dsigstore.test.local.maven.plugin.repo=" +
                        sigstoreMavenPluginTestClasspath.joinToString(File.pathSeparator) {
                            it.toRelativeString(projectDir)
                        },
            )
        }
    )
}
