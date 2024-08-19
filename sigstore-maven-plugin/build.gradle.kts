plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.depends-on-local-sigstore-java-repo")
    id("build-logic.depends-on-local-sigstore-maven-plugin-repo")
    id("de.benediktritter.maven-plugin-development") version "0.4.3"
}

description = "A Maven plugin for signing with Sigstore"

dependencies {
    compileOnly("org.apache.maven:maven-plugin-api:3.9.9")
    compileOnly("org.apache.maven:maven-core:3.9.8")
    compileOnly("org.apache.maven:maven-core:3.9.8")
    compileOnly("org.apache.maven.plugin-tools:maven-plugin-annotations:3.13.1")

    implementation(project(":sigstore-java"))
    implementation("org.bouncycastle:bcutil-jdk18on:1.78.1")
    implementation("org.apache.maven.plugins:maven-gpg-plugin:3.2.5")

    testImplementation("org.apache.maven.shared:maven-verifier:1.8.0")

    testImplementation(project(":sigstore-testkit"))

    sigstoreJavaRuntime(project(":sigstore-java")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
    sigstoreMavenPluginRuntime(project(":sigstore-maven-plugin")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
}
