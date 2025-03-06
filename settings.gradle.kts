rootProject.name = "sigstore-java-root"

if (JavaVersion.current() < JavaVersion.VERSION_17) {
    throw UnsupportedOperationException("Please use Java 17 or 21 for launching Gradle when building sigstore-java, the current Java is ${JavaVersion.current().majorVersion}")
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
