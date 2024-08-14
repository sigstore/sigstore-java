plugins {
  `java-library`
  `maven-publish`
  val sigstoreVersion = System.getProperty("sigstore.version") ?: "0.11.0"
  id("dev.sigstore.sign") version "$sigstoreVersion"
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
