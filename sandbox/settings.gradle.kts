rootProject.name = "sigstore-sandbox"

include("gradle-sign-file")
include("gradle-sign-java-library")
include("gradle-precompiled-plugin")
include("module-test")

// Include dev.sigstore.sign plugin
includeBuild("../")
