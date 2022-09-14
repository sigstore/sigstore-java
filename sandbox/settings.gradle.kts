rootProject.name = "sigstore-sandbox"

include("gradle-sign-file")
include("gradle-sign-java-library")

// Include dev.sigstore.sign plugin
includeBuild("../")
