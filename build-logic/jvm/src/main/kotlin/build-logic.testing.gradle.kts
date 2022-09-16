tasks.withType<Test>().configureEach {
    if (project.hasProperty("skipOidc")) {
        systemProperty("sigstore-java.test.skipOidc", project.findProperty("skipOidc")!!)
    }
}
