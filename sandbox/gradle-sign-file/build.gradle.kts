import dev.sigstore.sign.tasks.SigstoreSignFilesTask

plugins {
    id("java-base")
    id("dev.sigstore.sign-base")
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

val hello by tasks.registering(WriteProperties::class) {
    group = LifecycleBasePlugin.BUILD_GROUP
    description = "Generates a sample $name.properties file to sign"
    outputFile = layout.buildDirectory.file(
        "props/$name.properties"
    ).get().asFile
    property("hello", "world")
}

val signFile by tasks.registering(SigstoreSignFilesTask::class) {
    group = LifecycleBasePlugin.BUILD_GROUP
    description = "Signs file via Sigstore"
    signFile(hello.map { it.outputFile })
}
