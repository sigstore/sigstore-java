import com.google.protobuf.gradle.id

plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.build-info")
    id("org.jsonschema2dataclass") version "5.0.0"
    id("com.google.protobuf") version "0.9.6"
}

description = "A Java client for signing and verifying using Sigstore"

dependencies {
    compileOnly("org.immutables:gson:2.12.1")
    compileOnly("org.immutables:value-annotations:2.12.1")
    annotationProcessor("org.immutables:value:2.12.1")

    implementation(platform("com.google.http-client:google-http-client-bom:2.1.0"))
    implementation("com.google.http-client:google-http-client-apache-v2")
    implementation("com.google.http-client:google-http-client-gson")

    implementation("io.github.erdtman:java-json-canonicalization:1.1")

    // this requires inclusion of protos is src/main/proto
    protobuf("dev.sigstore:protobuf-specs:0.5.0")

    implementation(platform("com.google.protobuf:protobuf-bom:4.33.4"))
    implementation("com.google.protobuf:protobuf-java-util")

    // grpc deps
    implementation(platform("io.grpc:grpc-bom:1.78.0"))
    implementation("io.grpc:grpc-protobuf")
    implementation("io.grpc:grpc-stub")
    runtimeOnly("io.grpc:grpc-netty-shaded")
    compileOnly("org.apache.tomcat:annotations-api:6.0.53") // java 9+ only

    implementation("commons-codec:commons-codec:1.18.0")
    implementation("com.google.code.gson:gson:2.13.2")
    implementation("org.bouncycastle:bcutil-jdk18on:1.83")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.39.0"))
    implementation("com.google.oauth-client:google-oauth-client")
    implementation("com.google.oauth-client:google-oauth-client-jetty")
    implementation("com.google.oauth-client:google-oauth-client-java6")

    testImplementation(project(":sigstore-testkit"))
    testImplementation(platform("org.junit:junit-bom:5.14.2"))

    testImplementation(platform("org.mockito:mockito-bom:5.21.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")

    testImplementation("no.nav.security:mock-oauth2-server:0.5.10")
    testImplementation("com.squareup.okhttp3:mockwebserver:5.3.2")
    testImplementation("net.sourceforge.htmlunit:htmlunit:2.70.0")

    testImplementation("io.github.netmikey.logunit:logunit-core:2.0.0")
    testRuntimeOnly("io.github.netmikey.logunit:logunit-jul:2.0.0")
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.33.4"
    }
    plugins {
        id("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:1.78.0"
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
            "src/*/java/dev/sigstore/json/canonicalizer/*.java",
        )
    }
    format("conscrypt", com.diffplug.gradle.spotless.JavaExtension::class.java) {
        googleJavaFormat("1.24.0")
        licenseHeaderFile("$rootDir/config/conscryptLicenseHeader")
        target("src/*/java/dev/sigstore/encryption/certificates/transparency/*.java")
    }
    format("webPki", com.diffplug.gradle.spotless.JavaExtension::class.java) {
        googleJavaFormat("1.24.0")
        licenseHeaderFile("$rootDir/config/webPKILicenseHeader")
        target("src/*/java/dev/sigstore/json/canonicalizer/*.java")
    }
}

jsonSchema2Pojo {
    executions {
        create("rekor") {
            source.setFrom(files("${sourceSets.main.get().output.resourcesDir}/rekor/model"))
            targetDirectoryPrefix.set(layout.buildDirectory.dir("generated/sources/rekor-model/"))
            targetPackage.set("dev.sigstore.rekor")
            generateBuilders.set(true)
            annotationStyle.set("gson")
        }
    }
}

forbiddenApis {
    // Don't allow sigstore-java developers to directly call JsonFormat.parser(), use our wrapper instead
    // which allows for ignored fields.
    signaturesFiles = files("$rootDir/config/forbiddenApis.txt")
    suppressAnnotations = setOf("dev.sigstore.forbidden.SuppressForbidden")
}

// TODO: keep until these code gen plugins explicitly declare dependencies
tasks.named("sourcesJar") {
    dependsOn("generateJsonSchema2DataClassConfigRekor")
}

tasks.generateBuildInfo {
    packageName.set("dev.sigstore.buildinfo")
}
