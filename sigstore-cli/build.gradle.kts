plugins {
    id("build-logic.java")
    id("application")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("info.picocli:picocli:4.7.6")
    implementation("com.google.guava:guava:33.3.0-jre")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.36.0"))
    implementation("com.google.oauth-client:google-oauth-client")

    annotationProcessor("info.picocli:picocli-codegen:4.7.6")
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
