import org.gradle.api.attributes.Bundling
import org.gradle.api.attributes.Category
import org.gradle.kotlin.dsl.*
import java.io.File

plugins {
    java
}

val sigstoreJavaRuntime by configurations.creating {
    description = "declares dependencies that will be useful for testing purposes"
    isCanBeConsumed = false
    isCanBeResolved = false
}

val sigstoreJavaTestClasspath by configurations.creating {
    description = "sigstore-java in local repository for testing purposes"
    isCanBeConsumed = false
    isCanBeResolved = true
    extendsFrom(sigstoreJavaRuntime)
    attributes {
        attribute(Category.CATEGORY_ATTRIBUTE, objects.named("maven-repository"))
        attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
    }
}

tasks.test {
    dependsOn(sigstoreJavaTestClasspath)
    systemProperty("sigstore.test.current.version", version)
    val projectDir = layout.projectDirectory.asFile
    // This adds paths to the local repositories that contain currently-built sigstore-java
    // It enables testing both "sigstore-java from Central" and "sigstore-java build locally" in the plugin tests
    jvmArgumentProviders.add(
        // Gradle does not support Provider for systemProperties yet, see https://github.com/gradle/gradle/issues/12247
        CommandLineArgumentProvider {
            listOf(
                "-Dsigstore.test.local.maven.repo=" +
                        sigstoreJavaTestClasspath.joinToString(File.pathSeparator) {
                            it.toRelativeString(projectDir)
                        },
            )
        }
    )
}
