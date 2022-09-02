plugins {
    id("build-logic.repositories")
    id("build-logic.java-library")
    id("build-logic.reproducible-builds")
    id("build-logic.publish-to-central")
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}
