plugins {
    id("java")
}

group = "com.example.sigstore-gradle-sandbox"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("dev.sigstore:sigstore-common")
    implementation("dev.sigstore:sigstore-tuf")
    implementation("dev.sigstore:sigstore-java")
}
