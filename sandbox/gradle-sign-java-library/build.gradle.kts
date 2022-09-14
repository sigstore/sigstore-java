plugins {
    id("java-library")
    id("maven-publish")
    id("dev.sigstore.sign")
}

group = "com.example.sigstore-gradle-sandbox"
version = "1.0.0"

repositories {
    // A repository is required for fetching sigstore-java dependencies
    mavenCentral()
}

dependencies {
    // Optional configuration of a sigstore-java version to use
    // sigstoreClientClasspath("dev.sigstore:sigstore-java:0.1.0")
}

publishing {
    publications {
        create<MavenPublication>("javaLib") {
            from(components["java"])
        }
    }
    // This creates a repository under build/ directory for inspecting the results
    // You could use ./gradlew publishAllPublicationsToTmpRepository to publish artifacts to the repository
    repositories {
        maven {
            name = "tmp"
            setUrl(layout.buildDirectory.dir("tmp-repo"))
        }
    }
}
