rootProject.name = "sigstore-java-root"

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
