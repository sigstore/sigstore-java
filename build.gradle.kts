plugins {
    `java-library`
    id("com.diffplug.spotless") version "6.4.2"
    id("org.jsonschema2dataclass") version "4.2.0"
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
    useJUnitPlatform()
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

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:24.3.0"))
    implementation("com.google.http-client:google-http-client-apache-v2")
    implementation("com.google.http-client:google-http-client-gson")
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

println("${project.buildDir}")

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
