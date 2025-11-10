plugins {
    id("build-logic.kotlin-dsl-gradle-plugin")
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(project(":basics"))
    implementation(project(":build-parameters"))
    implementation("com.diffplug.spotless:com.diffplug.spotless.gradle.plugin:7.2.1")
    implementation("com.github.vlsi.gradle-extensions:com.github.vlsi.gradle-extensions.gradle.plugin:1.90")
    implementation("de.thetaphi.forbiddenapis:de.thetaphi.forbiddenapis.gradle.plugin:3.10")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin")
    implementation("org.jetbrains.dokka-javadoc:org.jetbrains.dokka-javadoc.gradle.plugin:2.1.0")
    implementation("com.github.autostyle:com.github.autostyle.gradle.plugin:4.0.1")
    implementation("net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:4.3.0")
}
