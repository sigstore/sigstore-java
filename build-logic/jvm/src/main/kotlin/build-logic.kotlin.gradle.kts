import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

plugins {
    id("java-library")
    id("build-logic.java")
    id("build-logic.testing")
    id("com.github.vlsi.gradle-extensions")
    id("com.github.autostyle")
    kotlin("jvm")
}

java {
    withSourcesJar()
}

autostyle {
    kotlin {
        file("$rootDir/config/licenseHeaderRaw").takeIf { it.exists() }?.let {
            licenseHeader(it.readText())
        }
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.named<KotlinJvmCompile>("compileKotlin") {
    compilerOptions {
        val targetJdkRelease = buildParameters.targetJavaVersion.toString()
        freeCompilerArgs.add("-Xjdk-release=$targetJdkRelease")
        jvmTarget.set(JvmTarget.fromTarget(targetJdkRelease))
    }
}

tasks.named<KotlinJvmCompile>("compileTestKotlin") {
    compilerOptions {
        freeCompilerArgs.add("-Xjdk-release=17")
        jvmTarget.set(JvmTarget.JVM_17)
    }
}
