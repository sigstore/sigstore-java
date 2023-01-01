import com.google.protobuf.gradle.id

plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("org.jsonschema2dataclass") version "5.0.0"
    id("com.google.protobuf") version "0.9.1"
}

description = "A Java client for signing and verifying using Sigstore"

dependencies {
    compileOnly("org.immutables:gson:2.9.3")
    compileOnly("org.immutables:value-annotations:2.9.3")
    annotationProcessor("org.immutables:value:2.9.3")

    implementation(platform("com.google.cloud:libraries-bom:26.2.0"))
    implementation("com.google.http-client:google-http-client-apache-v2")
    implementation("com.google.http-client:google-http-client-gson")

    implementation("io.github.erdtman:java-json-canonicalization:1.1")

    // grpc deps
    implementation(platform("io.grpc:grpc-bom:1.51.1"))
    implementation("io.grpc:grpc-protobuf")
    implementation("io.grpc:grpc-stub")
    runtimeOnly("io.grpc:grpc-netty-shaded")
    compileOnly("org.apache.tomcat:annotations-api:6.0.53") // java 9+ only

    implementation("commons-codec:commons-codec:1.15")
    implementation("com.google.code.gson:gson:2.10")
    implementation("org.bouncycastle:bcutil-jdk18on:1.72")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.72")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.34.1"))
    implementation("com.google.oauth-client:google-oauth-client")
    implementation("com.google.oauth-client:google-oauth-client-jetty")
    implementation("com.google.oauth-client:google-oauth-client-java6")

    testImplementation(project(":sigstore-testkit"))
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")

    testImplementation("org.mockito:mockito-core:4.10.0")
    testImplementation("no.nav.security:mock-oauth2-server:0.5.7")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.10.0")
    testImplementation("net.sourceforge.htmlunit:htmlunit:2.68.0")
    testImplementation("org.eclipse.jetty:jetty-server:11.0.13")
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.21.12"
    }
    plugins {
        id("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:1.51.1"
        }
    }
    generateProtoTasks {
        ofSourceSet("main").configureEach {
            plugins {
                id("grpc")
            }
            builtins {
                named("java") {
                    // Adds @javax.annotation.Generated annotation to the generated code
                    option("annotate_code")
                }
            }
        }
    }
}

spotless {
    java {
        targetExclude(
            "build/**/*.java",
            "src/*/java/dev/sigstore/encryption/certificates/transparency/*.java",
            "src/*/java/dev/sigstore/json/canonicalizer/*.java"
        )
    }
    format("conscrypt", com.diffplug.gradle.spotless.JavaExtension::class.java) {
        googleJavaFormat("1.6")
        licenseHeaderFile("$rootDir/config/conscryptLicenseHeader")
        target("src/*/java/dev/sigstore/encryption/certificates/transparency/*.java")
    }
    format("webPki", com.diffplug.gradle.spotless.JavaExtension::class.java) {
        googleJavaFormat("1.6")
        licenseHeaderFile("$rootDir/config/webPKILicenseHeader")
        target("src/*/java/dev/sigstore/json/canonicalizer/*.java")
    }
}

jsonSchema2Pojo {
    executions {
        create("rekor") {
            source.setFrom(files("${sourceSets.main.get().output.resourcesDir}/rekor/model"))
            targetDirectoryPrefix.set(file("$buildDir/generated/sources/rekor-model/"))
            targetPackage.set("dev.sigstore.rekor")
            generateBuilders.set(true)
            annotationStyle.set("gson")
        }
    }
}

// TODO: keep until these code gen plugins explicitly declare dependencies
tasks.named("sourcesJar") {
    dependsOn("generateJsonSchema2DataClassConfigRekor")
}
