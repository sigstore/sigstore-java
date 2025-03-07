plugins {
    id("java-library")
    id("build-logic.build-params")
}

tasks.withType<Test>().configureEach {
    buildParameters.testJdk?.let {
        javaLauncher.convention(javaToolchains.launcherFor(it))
    }
    if (project.hasProperty("skipOidc")) {
        systemProperty("sigstore-java.test.skipOidc", project.findProperty("skipOidc")!!)
    }
    if (project.hasProperty("org.gradle.jvmargs")) {
        systemProperty("sigstore-java.test.org.gradle.jvmargs", project.findProperty("org.gradle.jvmargs")!!)
    }
    if (project.hasProperty("skipStaging")) {
        systemProperty("sigstore-java.test.skipStaging", project.findProperty("skipStaging")!!)
    }
}
