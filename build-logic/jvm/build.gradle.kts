import buildlogic.embeddedKotlinDsl

plugins {
    id("build-logic.kotlin-dsl-gradle-plugin")
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(embeddedKotlinDsl())
    implementation("com.github.vlsi.gradle-extensions:com.github.vlsi.gradle-extensions.gradle.plugin:1.82")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin")
}
