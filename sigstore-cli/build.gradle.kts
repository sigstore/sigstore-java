plugins {
    id("build-logic.java")
    id("application")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("info.picocli:picocli:4.7.1")
    implementation("com.google.guava:guava:31.1-jre")

    annotationProcessor("info.picocli:picocli-codegen:4.7.1")
}

tasks.compileJava {
    options.compilerArgs.add("-Aproject=${project.group}/${project.name}")
}

application {
    mainClass.set("dev.sigstore.cli.Sigstore")
}
tasks.run.configure {
    workingDir = rootProject.projectDir
}
