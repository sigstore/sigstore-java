plugins {
    id("build-logic.kotlin-dsl-gradle-plugin")
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(project(":basics"))
    implementation(project(":jvm"))
    implementation("dev.sigstore.build-logic:gradle-plugin")
    implementation("dev.sigstore:sigstore-gradle-sign-plugin:1.3.0")
    implementation("com.gradle.plugin-publish:com.gradle.plugin-publish.gradle.plugin:1.3.1")
}
