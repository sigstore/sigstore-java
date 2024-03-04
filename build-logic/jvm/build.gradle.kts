import buildlogic.embeddedKotlinDsl

plugins {
    id("build-logic.kotlin-dsl-gradle-plugin")
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(embeddedKotlinDsl())
    implementation("com.diffplug.spotless:com.diffplug.spotless.gradle.plugin:6.25.0")
    implementation("com.github.vlsi.gradle-extensions:com.github.vlsi.gradle-extensions.gradle.plugin:1.90")
    implementation("de.thetaphi.forbiddenapis:de.thetaphi.forbiddenapis.gradle.plugin:3.6")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin")
    implementation("org.jetbrains.dokka:org.jetbrains.dokka.gradle.plugin:1.9.20")
    implementation("com.github.autostyle:com.github.autostyle.gradle.plugin:4.0")
    implementation("net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:3.1.0")
}
