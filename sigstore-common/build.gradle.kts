plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.build-info")
}

description = "Common utilities for Sigstore Java"

tasks.jar {
    manifest {
        attributes["Automatic-Module-Name"] = "dev.sigstore.common"
    }
}

dependencies {
    compileOnly("org.immutables:value-annotations:2.12.2")
    annotationProcessor("org.immutables:value:2.12.2")
    api(platform("com.google.http-client:google-http-client-bom:2.2.0"))
    api("com.google.http-client:google-http-client-apache-v5")
    api("com.google.http-client:google-http-client-gson")

    api("io.github.erdtman:java-json-canonicalization:1.1")
    api("com.google.code.gson:gson:2.14.0")
    implementation("com.google.guava:guava:33.7.1-jre")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation(platform("org.mockito:mockito-bom:5.23.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}

forbiddenApis {
    signaturesFiles = files("$rootDir/config/forbiddenApis.txt")
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
    ignoreSignaturesOfMissingClasses = true
}

tasks.generateBuildInfo {
    packageName.set("dev.sigstore.common.buildinfo")
}

spotless {
    java {
        targetExclude(
            "build/**/*.java",
            "src/*/java/dev/sigstore/common/json/canonicalizer/*.java",
        )
    }
    format("webPki", com.diffplug.gradle.spotless.JavaExtension::class.java) {
        googleJavaFormat("1.35.0")
        licenseHeaderFile("$rootDir/config/webPKILicenseHeader")
        target("src/*/java/dev/sigstore/common/json/canonicalizer/*.java")
    }
}
