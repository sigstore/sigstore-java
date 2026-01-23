plugins {
    id("build-logic.kotlin-dsl-gradle-plugin")
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(project(":build-parameters"))
    implementation(project(":basics"))
    implementation(project(":jvm"))
    implementation("dev.sigstore.build-logic:gradle-plugin")
    implementation("dev.sigstore:sigstore-gradle-sign-plugin:2.0.0")
    implementation("com.gradle.plugin-publish:com.gradle.plugin-publish.gradle.plugin:2.0.0")
    implementation("com.gradleup.nmcp:com.gradleup.nmcp.gradle.plugin:1.4.0")
}
