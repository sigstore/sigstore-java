plugins {
    `kotlin-dsl`
}

group = "dev.sigstore.build-logic"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

// We use precompiled script plugins (== plugins written as src/kotlin/build-logic.*.gradle.kts files,
// and we need to declare dependency on org.gradle.kotlin.kotlin-dsl:org.gradle.kotlin.kotlin-dsl.gradle.plugin
// to make it work.
// Unfortunately, Gradle does not expose the version of `kotlin-dsl` in-core plugin, so we call `kotlin-dsl`
// on our own PluginDependenciesSpec object, so it leaks the version to us.
// See https://github.com/gradle/gradle/issues/17016
val kotlinDslVersion = PluginDependenciesSpec { id ->
    object : PluginDependencySpec {
        var version: String? = null
        override fun version(version: String?) = apply { this.version = version }
        override fun apply(apply: Boolean) = this
        override fun toString() = version ?: ""
    }
}.`kotlin-dsl`.toString()

dependencies {
    implementation("org.gradle.kotlin.kotlin-dsl:org.gradle.kotlin.kotlin-dsl.gradle.plugin:$kotlinDslVersion")
}

kotlinDslPluginOptions {
    jvmTarget.set("11")
}
