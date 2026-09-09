plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.depends-on-local-sigstore-java-repo")
    id("build-logic.depends-on-local-sigstore-maven-plugin-repo")
    id("org.gradlex.maven-plugin-development") version "1.0.3"
}

description = "A Maven plugin for signing with Sigstore"

val mavenDistribution =
    configurations.create("mavenDistribution") {
        isCanBeConsumed = false
        isCanBeResolved = true
        isTransitive = false
    }

dependencies {
    compileOnly("org.apache.maven:maven-plugin-api:3.10.0")
    compileOnly("org.apache.maven:maven-core:3.10.0")
    compileOnly("org.apache.maven.plugin-tools:maven-plugin-annotations:3.16.0")

    implementation(project(":sigstore-java"))
    implementation("org.bouncycastle:bcutil-jdk18on:1.86")
    implementation("org.apache.maven.plugins:maven-gpg-plugin:3.2.8")

    testImplementation("org.apache.maven.executor:maven-executor:1.0.0")

    testImplementation(project(":sigstore-testkit"))

    mavenDistribution("org.apache.maven:apache-maven:3.10.0:bin@zip")

    sigstoreJavaRuntime(project(":sigstore-common"))
    sigstoreJavaRuntime(project(":sigstore-tuf"))
    sigstoreJavaRuntime(project(":sigstore-java")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
    sigstoreMavenPluginRuntime(project(":sigstore-maven-plugin")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
}

val unpackMavenDistribution =
    tasks.register<Sync>("unpackMavenDistribution") {
        from(mavenDistribution.elements.map { zipTree(it.single()) })
        into(layout.buildDirectory.dir("maven-distro"))
    }

tasks.test {
    dependsOn(unpackMavenDistribution)
    jvmArgumentProviders.add(
        CommandLineArgumentProvider {
            val mavenHome =
                unpackMavenDistribution
                    .get()
                    .destinationDir
                    .listFiles()!!
                    .single()
            listOf("-Dmaven.home=${mavenHome.absolutePath}")
        },
    )
}
