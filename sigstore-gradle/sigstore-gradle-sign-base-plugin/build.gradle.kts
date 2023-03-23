plugins {
    id("build-logic.kotlin-dsl-published-gradle-plugin")
    id("build-logic.test-junit5")
}

description = "Gradle plugin with the base set of tasks and configurations for Sigstore singing (no signing is done by default)"

dependencies {
    compileOnly(project(":sigstore-java"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.14.2")

    sigstoreJavaRuntime(project(":sigstore-java")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }
    testImplementation(project(":sigstore-testkit"))
}

pluginBundle {
    website = "https://github.com/sigstore/sigstore-java"
    vcsUrl = "https://github.com/sigstore/sigstore-java.git"
    tags = listOf("sigstore", "sign")
}

gradlePlugin {
    plugins {
        named("dev.sigstore.sign-base") {
            displayName = "Base tasks and configurations for signing artifacts via Sigstore"
            description = "The plugin provides tasks and configurations so you can wire your own Sigstore signing. " +
                "If you want sign everything with standard configuration, then consider dev.sigstore.sign plugin instead"
        }
    }
}
