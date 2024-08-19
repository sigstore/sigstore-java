import net.ltgt.gradle.errorprone.errorprone

plugins {
    java
}

if (!project.hasProperty("skipErrorprone")) {
    apply(plugin = "net.ltgt.errorprone")

    dependencies {
        "errorprone"("com.google.errorprone:error_prone_core:2.30.0")
        "annotationProcessor"("com.google.guava:guava-beta-checker:1.0")
    }

    tasks.withType<JavaCompile>().configureEach {
        if ("Test" in name) {
            // Ignore warnings in test code
            options.errorprone.isEnabled.set(false)
        } else {
            options.compilerArgs.addAll(listOf("-Xmaxerrs", "10000", "-Xmaxwarns", "10000"))
            options.errorprone {
                disableWarningsInGeneratedCode.set(true)
                enable(
                    "PackageLocation"
                )
            }
        }
    }
}
