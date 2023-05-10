plugins {
    id("build-logic.java")
    id("application")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("info.picocli:picocli:4.7.3")
    implementation("com.google.guava:guava:31.1-jre")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.34.1"))
    implementation("com.google.oauth-client:google-oauth-client")

    annotationProcessor("info.picocli:picocli-codegen:4.7.3")
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
