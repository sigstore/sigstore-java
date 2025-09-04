import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    id("build-logic.java")
    id("application")
    id("com.gradleup.shadow") version "9.0.0-rc3"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("info.picocli:picocli:4.7.6")
    implementation("com.google.guava:guava:33.4.8-jre")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.39.0"))
    implementation("com.google.oauth-client:google-oauth-client")

    implementation("org.eclipse.jetty:jetty-server:11.0.24")
    implementation("org.eclipse.jetty:jetty-servlet:11.0.24")

    implementation("org.slf4j:slf4j-simple:2.0.17")

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

tasks.register<ShadowJar>("serverShadowJar") {
    archiveBaseName.set("tuf-cli-server")
    archiveClassifier.set("all")
    archiveVersion.set("")

    mergeServiceFiles()

    from(sourceSets.main.get().output)
    configurations = listOf(project.configurations.runtimeClasspath.get())

    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")

    manifest {
        attributes("Main-Class" to "dev.sigstore.tuf.cli.TufConformanceServer")
    }
}
