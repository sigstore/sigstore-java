rootProject.name = "sigstore-sandbox"

include("gradle-sign-file")
include("gradle-sign-java-library")
include("gradle-precompiled-plugin")

// Include dev.sigstore.sign plugin
includeBuild("../")
