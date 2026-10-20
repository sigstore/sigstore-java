plugins {
    `java-base`
    id("java")
}

group = "com.example.sigstore-gradle-sandbox"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
}

val sigstoreVersion = "2.4.0-SNAPSHOT"

dependencies {
    implementation("dev.sigstore:sigstore-common:$sigstoreVersion")
    implementation("dev.sigstore:sigstore-java:$sigstoreVersion")
}

tasks.compileJava {
    options.compilerArgumentProviders.add(CommandLineArgumentProvider {
        listOf(
            "--module-path", classpath.asPath,
        )
    })
}
