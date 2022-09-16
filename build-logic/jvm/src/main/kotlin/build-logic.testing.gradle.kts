tasks.withType<Test>().configureEach {
    if (project.hasProperty("skipOidc")) {
        systemProperty("sigstore-java.test.skipOidc", project.findProperty("skipOidc")!!)
    }
    if (project.hasProperty("org.gradle.jvmargs")) {
        systemProperty("sigstore-java.test.org.gradle.jvmargs", project.findProperty("org.gradle.jvmargs")!!)
    }
}
