plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.depends-on-local-sigstore-java-repo")
    id("build-logic.depends-on-local-sigstore-maven-plugin-repo")
    id("org.gradlex.maven-plugin-development") version "1.0.3"
}

description = "A Maven plugin for signing with Sigstore"

dependencies {
    compileOnly("org.apache.maven:maven-plugin-api:3.9.12")
    compileOnly("org.apache.maven:maven-core:3.9.12")
    compileOnly("org.apache.maven.plugin-tools:maven-plugin-annotations:3.15.2")

    implementation(project(":sigstore-java"))
    implementation("org.bouncycastle:bcutil-jdk18on:1.83")
    implementation("org.apache.maven.plugins:maven-gpg-plugin:3.2.8")

    testImplementation("org.apache.maven.shared:maven-verifier:1.8.0")

    testImplementation(project(":sigstore-testkit"))

    sigstoreJavaRuntime(project(":sigstore-java")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
    sigstoreMavenPluginRuntime(project(":sigstore-maven-plugin")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
}
