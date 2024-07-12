plugins {
    id("com.gradle.plugin-publish")
    id("build-logic.repositories")
    id("build-logic.kotlin")
    id("build-logic.kotlin-dsl-gradle-plugin")
    id("build-logic.reproducible-builds")
    id("build-logic.dokka-javadoc")
    id("build-logic.publish-to-central")
    id("build-logic.depends-on-local-sigstore-java-repo")
}
