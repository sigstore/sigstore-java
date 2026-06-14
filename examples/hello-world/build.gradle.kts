plugins {
  `java-library`
  `maven-publish`
  val sigstoreVersion = System.getProperty("sigstore.version") ?: "2.2.0"
  id("dev.sigstore.sign") version "$sigstoreVersion"
  signing
}

version = "1.0.0"
group = "com.example"

// required to resolve sigstore-java
repositories {
  mavenLocal() // for testing against dev builds
  mavenCentral()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
    repositories {
        maven {
            name = "examples"
            url = uri(layout.buildDirectory.dir("example-repo"))
        }
    }
}

// sigstore signing doesn't require additional setup in build.gradle.kts

// PGP signing setup for the purposes of this example.
signing {
    val signingKey = project.findProperty("signingKey") as String?
    val signingPassword = project.findProperty("signingPassword") as String?
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["maven"])
}
