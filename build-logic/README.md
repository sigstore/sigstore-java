# Build logic for Sigstore Java

This is a subset of extra plugins for factoring out
the common patterns from the common build logic.

The recommended approach is to use build composition, so every build script
should list all its prerequisites in the top-most `plugins { ... }` block.

The use of `allprojects` and `subprojects` is an anti-pattern as it makes it hard to identify
the configuration for a given project.

Let us consider an example (see `/sigstore-gradle-sign-base-plugin/build.gradle.kts`):

```kotlin
plugins {
    id("build-logic.kotlin-dsl-published-gradle-plugin")
    id("build-logic.test-junit5")
}

description = "Gradle plugin with the base set of tasks and configurations for Sigstore singing (no signing is done by default)"

dependencies {
    compileOnly(project(":sigstore-java"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")

    testImplementation(project(":sigstore-testkit"))
}
```

It means that we deal with a Gradle plugin written in Kotlin that will be published to Central,
and which uses JUnit 5 for testing.

If you want to see what the logic does, you could open `buildlogic.kotlin-dsl-published-plugin.gradle.kts`
and `buildlogic.test-junit5.gradle.kts`.
