plugins {
    id("build-logic.java")
    id("application")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
}

application {
    mainClass.set("dev.sigstore.conformance.Main")
}
