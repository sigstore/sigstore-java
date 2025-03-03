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
    implementation("com.google.guava:guava:33.4.0-jre")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.38.0"))
    implementation("com.google.oauth-client:google-oauth-client")

    annotationProcessor("info.picocli:picocli-codegen:4.7.6")
}

tasks.compileJava {
    options.compilerArgs.add("-Aproject=${project.group}/${project.name}")
}

application {
    mainClass.set("dev.sigstore.tuf.cli.Tuf")
}

distributions.main {
    contents {
        from("tuf-cli.xfails") {
            into("bin")
        }
    }
}

tasks.run.configure {
    workingDir = rootProject.projectDir
}
