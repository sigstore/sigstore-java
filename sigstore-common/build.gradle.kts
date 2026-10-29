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
    compileOnly("org.immutables:value-annotations:2.12.3")
    annotationProcessor("org.immutables:value:2.12.3")
    api(platform("com.google.http-client:google-http-client-bom:2.2.0"))
    api("com.google.http-client:google-http-client-apache-v5")
    api("com.google.http-client:google-http-client-gson")
    api("com.google.code.gson:gson:2.14.0")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation(platform("org.mockito:mockito-bom:5.24.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}

forbiddenApis {
    signaturesFiles = files("$rootDir/config/forbiddenApis-common.txt")
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
}

tasks.generateBuildInfo {
    packageName.set("dev.sigstore.common.buildinfo")
}

spotless {
    java {
        targetExclude(
            "build/**/*.java",
        )
    }
}
