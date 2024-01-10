plugins {
    id("build-logic.root-build")
    // The Kotlin Gradle plugin was loaded multiple times in different subprojects, which is not supported and may break the build.
    `embedded-kotlin` apply false
}

val calculatedVersion = property("version") as String + (if (hasProperty("release")) "" else "-SNAPSHOT")

allprojects {
    version = calculatedVersion
}
