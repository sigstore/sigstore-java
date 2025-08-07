plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "sigstore-java-root"

// TODO: update when ossfuzz bumps Java to 21, see https://github.com/google/oss-fuzz/issues/14266
if (!System.getenv("CIFUZZ").equals("true", ignoreCase = true) && JavaVersion.current() < JavaVersion.VERSION_21) {
    throw UnsupportedOperationException("Please use Java 21+ for launching Gradle when building ${rootProject.name}, the current Java is ${JavaVersion.current().majorVersion}. " +
            "If you want to execute tests with a different Java version, use -PjdkTestVersion=${JavaVersion.current().majorVersion}")
}

includeBuild("build-logic-commons")
includeBuild("build-logic")

include("sigstore-java")
include("sigstore-gradle:sigstore-gradle-sign-base-plugin")
include("sigstore-gradle:sigstore-gradle-sign-plugin")
include("sigstore-testkit")
include("sigstore-maven-plugin")

include("sigstore-cli")
include("tuf-cli")

include("fuzzing")
