import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.ofSourceSet
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc

plugins {
    `java-library`
    `maven-publish`
    id("com.diffplug.spotless") version "6.4.2"
    id("org.jsonschema2dataclass") version "4.2.0"
    id("com.google.protobuf") version "0.8.17"
}

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

sourceSets["main"].java {
    srcDirs("build/generated/sources/rekor-model/main")
}

tasks.withType<Test> {
    testLogging {
        events("passed", "skipped", "failed")
    }
    // be very verbose in CI
    if (environment.containsKey("CI")) {
        testLogging {
            showStandardStreams = true
            showExceptions = true
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }
}

// Reproducible builds https://docs.gradle.org/current/userguide/working_with_files.html#sec:reproducible_archives
tasks.withType<AbstractArchiveTask>() {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.test {
    useJUnitPlatform() {
        includeTags("none()")
    }
}

// a special test grouping for tests that require a valid gha oidc token
task<Test>("testGithubOidc") {
    useJUnitPlatform() {
        includeTags("github_oidc")
    }
}

// manual test groups that are *not* run in CI, these should be run before
task<Test>("testManual") {
    useJUnitPlatform() {
        includeTags("manual")
    }
}

sourceSets["main"].java {
    srcDirs("build/generated/source/proto/main/grpc")
    srcDirs("build/generated/source/proto/main/java")
}

dependencies {
    compileOnly("org.immutables:gson:2.8.2")
    compileOnly("org.immutables:value-annotations:2.8.2")
    annotationProcessor("org.immutables:value:2.8.2")

    implementation(platform("com.google.cloud:libraries-bom:24.3.0"))
    implementation("com.google.http-client:google-http-client-apache-v2")
    implementation("com.google.http-client:google-http-client-gson")

    implementation("io.github.erdtman:java-json-canonicalization:1.1")

    // grpc deps
    implementation(platform("io.grpc:grpc-bom:1.46.0"))
    implementation("io.grpc:grpc-protobuf")
    implementation("io.grpc:grpc-stub")
    runtimeOnly("io.grpc:grpc-netty-shaded")
    compileOnly("org.apache.tomcat:annotations-api:6.0.53") // java 9+ only

    implementation("com.google.code.gson:gson:2.8.9")
    implementation("org.conscrypt:conscrypt-openjdk-uber:2.5.2") {
        because("contains library code for all platforms")
    }
    implementation("org.bouncycastle:bcutil-jdk18on:1.71")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.71")

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.33.3"))
    implementation("com.google.oauth-client:google-oauth-client")
    implementation("com.google.oauth-client:google-oauth-client-jetty")
    implementation("com.google.oauth-client:google-oauth-client-java6")

    testImplementation(platform("org.junit:junit-bom:5.8.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")

    testImplementation("no.nav.security:mock-oauth2-server:0.4.4")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.9.3")
    testImplementation("net.sourceforge.htmlunit:htmlunit:2.61.0")

    implementation("javax.validation:validation-api:2.0.1.Final")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.19.2"
    }
    plugins {
        id("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:1.45.1"
        }
    }
    generateProtoTasks {
        ofSourceSet("main").forEach() {
            it.plugins {
                id("grpc")
            }
        }
    }
}

spotless {
    kotlinGradle {
        target("*.gradle.kts") // default target for kotlinGradle
        ktlint()
    }
    format("misc") {
        target("*.md", ".gitignore")

        trimTrailingWhitespace()
        indentWithSpaces()
        endWithNewline()
    }
    java {
        googleJavaFormat("1.6")
        licenseHeaderFile("config/licenseHeader")
        targetExclude("build/**/*.java")
    }
}

jsonSchema2Pojo {
    source.setFrom(files("${sourceSets.main.get().output.resourcesDir}/rekor/model"))
    targetDirectoryPrefix.set(file("${project.buildDir}/generated/sources/rekor-model/"))
    targetPackage.set("dev.sigstore.rekor")
    generateBuilders.set(true)
    annotationStyle.set("gson")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = rootProject.name
            from(components["java"])

            pom {
                name.set(rootProject.name)
                description.set("A java client for signing and verifying using sigstore")
                url.set("https://github.com/sigstore/sigstore-java")

                // https://docs.gradle.org/current/userguide/publishing_maven.html#publishing_maven:resolved_dependencies
                versionMapping {
                    usage("java-api") {
                        fromResolutionOf("runtimeClasspath")
                    }
                    usage("java-runtime") {
                        fromResolutionResult()
                    }
                }

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        organization.set("sigstore authors")
                        organizationUrl.set("https://sigstore.dev")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/sigstore/sigstore-java.git")
                    developerConnection.set("scm:git:ssh://github.com/sigstore/sigstore-java.git")
                    url.set("https://github.com/sigstore/sigstore-java")
                }
            }
        }
    }
}
