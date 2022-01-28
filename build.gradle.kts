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

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:24.3.0"))
    implementation("com.google.http-client:google-http-client-apache-v2")
    implementation("com.google.api-client:google-api-client-gson:1.31.5")

    implementation("com.google.code.gson:gson:2.8.9")

    testImplementation("junit:junit:4.12")
    testImplementation("com.nimbusds:oauth2-oidc-sdk:6.21.2")
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.18")
    testImplementation("org.bouncycastle:bcutil-jdk15on:1.70")
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
