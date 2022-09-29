plugins {
    id("build-logic.root-build")
    // It does not support participating in precompiled script plugins
    id("com.github.vlsi.stage-vote-release") version "1.82"
    // The Kotlin Gradle plugin was loaded multiple times in different subprojects, which is not supported and may break the build.
    kotlin("jvm") version "1.7.20" apply false
}

val buildVersion = "${findProperty("version")}${releaseParams.snapshotSuffix}"

println("Building Sigstore Java $buildVersion")

val isReleaseVersion = rootProject.releaseParams.release.get()

releaseParams {
    tlp.set("sigstore-java")
    organizationName.set("sigstore")
    componentName.set("sigstore-java")
    prefixForProperties.set("s01")
    svnDistEnabled.set(false)
    sitePreviewEnabled.set(false)
    nexus {
        prodUrl.set(uri("https://s01.oss.sonatype.org"))
    }
    voteText.set {
        """
        ${it.componentName} v${it.version}-rc${it.rc} is ready for preview.

        Git SHA: ${it.gitSha}
        Staging repository: ${it.nexusRepositoryUri}
        """.trimIndent()
    }
}

allprojects {
    version = project.findProperty("version") as? String ?: rootProject.version
}
