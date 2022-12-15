plugins {
    id("java")
    id("application")
    id("com.diffplug.spotless") version "6.11.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.google.guava:guava:31.1-jre")
}

spotless {
    kotlinGradle {
        target("*.gradle.kts") // default target for kotlinGradle
        ktlint()
    }
    format("misc") {
        target("*.md", ".gitignore", "**/*.yaml")

        trimTrailingWhitespace()
        indentWithSpaces()
        endWithNewline()
    }
    java {
        googleJavaFormat("1.6")
        licenseHeaderFile("$rootDir/config/licenseHeader")
    }
}

application {
    mainClass.set("dev.sigstore.Main")
}
