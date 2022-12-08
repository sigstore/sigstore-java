plugins {
    id("build-logic.kotlin-dsl-published-gradle-plugin")
    id("build-logic.test-junit5")
}

description = "Gradle plugin with the base set of tasks and configurations for Sigstore singing (no signing is done by default)"

dependencies {
    compileOnly(project(":sigstore-java"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.14.1")

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
            displayName = "Sign artifacts via Sigstore"
            description = "Plugin for signing artifacts via Sigstore"
        }
    }
}
