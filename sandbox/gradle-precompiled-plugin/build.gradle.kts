plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
}

dependencies {
    // dev.sigstore.sign:dev.sigsore.sign.gradle.plugin is preferable,
    // however Gradle does not recognize .gradle.plugin within included build,
    // so we use the fallback
    implementation("dev.sigstore:sigstore-gradle-sign-plugin")
}
