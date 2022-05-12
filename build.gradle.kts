plugins {
    `java-library`
    id("com.diffplug.spotless") version "6.3.0"
}

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.compileTestJava {
    sourceCompatibility = JavaVersion.VERSION_11.majorVersion
    targetCompatibility = JavaVersion.VERSION_11.majorVersion
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
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

    implementation(platform("com.google.oauth-client:google-oauth-client-bom:1.33.3"))
    implementation("com.google.oauth-client:google-oauth-client")
    implementation("com.google.oauth-client:google-oauth-client-jetty")
    implementation("com.google.oauth-client:google-oauth-client-java6")

    testImplementation(platform("org.junit:junit-bom:5.8.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("com.nimbusds:oauth2-oidc-sdk:6.21.2")
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.18")
    testImplementation("no.nav.security:mock-oauth2-server:0.4.4")

    testImplementation("org.bouncycastle:bcutil-jdk15on:1.70")
    testImplementation("net.sourceforge.htmlunit:htmlunit:2.61.0")
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
    }
}
