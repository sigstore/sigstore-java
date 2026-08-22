import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

plugins {
    id("build-logic.kotlin")
    id("build-logic.repositories")
    id("build-logic.test-junit5")
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.google.code.gson:gson:2.14.0")
    implementation("com.google.guava:guava:33.6.0-jre")

    // This is different from typical "testImplementation" dependencies, because
    // testkit exposes junit5 dependencies in its API (e.g. annotations)
    api(platform("org.junit:junit-bom:5.14.4"))
    api("org.junit.jupiter:junit-jupiter-api")
    api("org.junit.jupiter:junit-jupiter-params")
    implementation("org.junit.jupiter:junit-jupiter")
    api("org.assertj:assertj-core:3.27.7")
    api(gradleTestKit())
}

tasks.named<JavaCompile>("compileJava") {
    options.release.set(17)
}

tasks.named<KotlinJvmCompile>("compileKotlin") {
    compilerOptions {
        freeCompilerArgs.set(listOf("-Xjdk-release=17"))
        jvmTarget.set(JvmTarget.JVM_17)
    }
}
