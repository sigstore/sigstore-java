plugins {
    id("build-logic.java")
    id("application")
    id("org.graalvm.buildtools.native") version "0.11.0"
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

    implementation("com.google.api:gax-grpc:2.68.2")

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

graalvmNative {
    binaries.getByName("main") {
        sharedLibrary.set(false)
        mainClass.set("dev.sigstore.cli.Sigstore")
        imageName.set("sigstore-cli")

        resources {
            autodetection {
                enabled.set(true)
            }
        }

        buildArgs.add("--no-fallback")
        buildArgs.add("--enable-url-protocols=http,https")
        buildArgs.add("--initialize-at-run-time=org.bouncycastle,io.grpc.netty.shaded.io.netty")
    }
}
