plugins {
    id("build-logic.java-published-library")
}

description = "Common utilities for Sigstore Java"

tasks.jar {
    manifest {
        attributes["Automatic-Module-Name"] = "dev.sigstore.common"
    }
}

dependencies {
    api("com.google.code.gson:gson:2.15.0")
}

forbiddenApis {
    signaturesFiles = files("$rootDir/config/forbiddenApis-common.txt")
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
}

spotless {
    java {
        targetExclude(
            "build/**/*.java",
        )
    }
}
