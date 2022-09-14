tasks.withType<Test>().configureEach {
    if (project.hasProperty("skipOidc")) {
        println("skipOidc: ${project.findProperty("skipOidc")}")
        systemProperty("sigstore-java.test.skipOidc", project.findProperty("skipOidc")!!)
    }
}
