plugins {
    id("build-logic.build-params")
    id("build-logic.repositories")
    id("build-logic.java-library")
    id("build-logic.reproducible-builds")
    id("build-logic.publish-to-central")
    id("build-logic.signing")
}

java {
    if (!buildParameters.skipJavadoc) {
        withJavadocJar()
    }
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}

signing.sign(publishing.publications["mavenJava"])
