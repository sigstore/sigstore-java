plugins {
    id("build-logic.kotlin-dsl-published-gradle-plugin")
    id("build-logic.test-junit5")
}

description = "Gradle plugin to that automatically signs all Publications in Sigstore"

dependencies {
    api(project(":sigstore-gradle:sigstore-gradle-sign-base-plugin"))

    sigstoreJavaRuntime(project(":sigstore-java")) {
        because("Test code needs access locally-built sigstore-java as a Maven repository")
    }

    testImplementation(project(":sigstore-testkit"))
}

gradlePlugin {
    website.set("https://github.com/sigstore/sigstore-java")
    vcsUrl.set("https://github.com/sigstore/sigstore-java.git")
    plugins {
        named("dev.sigstore.sign") {
            displayName = "Sign artifacts via Sigstore"
            description = "The plugin signs all artifacts with Sigstore and attaches signature bundles"
            tags.set(listOf("sigstore", "sign"))
        }
    }
}
configure<PublishingExtension> {
    repositories {
        maven(layout.buildDirectory.dir("tmp-repo")) {
            name = "tmp"
        }
    }
}
