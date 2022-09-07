plugins {
    id("java-library")
    id("org.gradle.kotlin.kotlin-dsl") // this is 'kotlin-dsl' without version
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.validatePlugins {
    failOnWarning.set(true)
    enableStricterValidation.set(true)
}

kotlinDslPluginOptions {
    jvmTarget.set("11")
}
