plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
    id("build-logic.build-info")
}

description = "HTTP client utilities for Sigstore Java"

tasks.jar {
    manifest {
        attributes["Automatic-Module-Name"] = "dev.sigstore.http"
    }
}

dependencies {
    compileOnly("org.immutables:value-annotations:2.12.3")
    annotationProcessor("org.immutables:value:2.12.3")

    compileOnly(project(":sigstore-common")) {
        because("@SuppressForbidden is a compile-time only annotation")
    }

    api(platform("com.google.http-client:google-http-client-bom:2.2.0"))
    api("com.google.http-client:google-http-client-apache-v5")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation(platform("org.mockito:mockito-bom:5.23.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}

forbiddenApis {
    signaturesFiles = files("$rootDir/config/forbiddenApis-http.txt")
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
}

tasks.generateBuildInfo {
    packageName.set("dev.sigstore.http.buildinfo")
}
