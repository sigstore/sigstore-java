plugins {
    id("java")
    id("application")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.google.guava:guava:31.1-jre")
}

application {
    mainClass.set("dev.sigstore.Main")
}
