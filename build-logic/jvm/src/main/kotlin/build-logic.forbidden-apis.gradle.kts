import de.thetaphi.forbiddenapis.gradle.CheckForbiddenApisExtension

plugins {
    id("build-logic.build-params")
}

if (!buildParameters.skipForbiddenApis) {
    apply(plugin = "de.thetaphi.forbiddenapis")

    configure<CheckForbiddenApisExtension> {
        failOnUnsupportedJava = false
        // ForbiddenApiException: Check for forbidden API calls failed while scanning class 'Dev_sigstore_sign_base_gradle'
        // (dev.sigstore.sign-base.gradle.kts): java.lang.ClassNotFoundException: kotlin.script.experimental.jvm.RunnerKt
        // (while looking up details about referenced class 'kotlin.script.experimental.jvm.RunnerKt')
        failOnMissingClasses = false
        // See https://github.com/policeman-tools/forbidden-apis/wiki/BundledSignatures
        bundledSignatures.addAll(
            listOf(
                "jdk-deprecated",
                "jdk-internal",
                "jdk-non-portable",
                "jdk-unsafe"
            )
        )
    }
}
