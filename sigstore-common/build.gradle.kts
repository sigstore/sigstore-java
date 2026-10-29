plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
}

description = "Common utilities for Sigstore Java"

tasks.jar {
    manifest {
        attributes["Automatic-Module-Name"] = "dev.sigstore.common"
    }
}

dependencies {
    api("com.google.code.gson:gson:2.14.0")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation(platform("org.mockito:mockito-bom:5.24.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}

forbiddenApis {
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
}

spotless {
    java {
        targetExclude(
            "build/**/*.java",
        )
    }
}
