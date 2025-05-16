plugins {
    id("java-base")
    id("org.jetbrains.dokka-javadoc")
    id("build-logic.build-params")
}

java {
    if (!buildParameters.skipJavadoc) {
        // Workaround https://github.com/gradle/gradle/issues/21933, so it adds javadocElements configuration
        withJavadocJar()
    }
}

val dokkaJar by tasks.registering(Jar::class) {
    group = LifecycleBasePlugin.BUILD_GROUP
    description = "Assembles a jar archive containing javadoc"
    from(tasks.dokkaGeneratePublicationJavadoc)
    archiveClassifier.set("javadoc")
}

if (!buildParameters.skipJavadoc) {
    configurations[JavaPlugin.JAVADOC_ELEMENTS_CONFIGURATION_NAME].outgoing.artifact(dokkaJar)
}
