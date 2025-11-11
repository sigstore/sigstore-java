plugins {
    id("java-library")
    id("build-logic.build-params")
}

tasks.withType<Test>().configureEach {
    buildParameters.testJdk?.let {
        javaLauncher.convention(javaToolchains.launcherFor(it))
        // Pass JAVA_HOME for testJdkVersion to the test task, so it can spawn Gradle using the given Java home
        jvmArgumentProviders.add(
            CommandLineArgumentProvider {
                listOf("-Dsigstore-java.test.JAVA_HOME=${javaLauncher.get().metadata.installationPath.asFile.absolutePath}")
            }
        )
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
