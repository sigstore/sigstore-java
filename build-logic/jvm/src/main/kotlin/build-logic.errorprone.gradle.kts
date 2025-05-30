import net.ltgt.gradle.errorprone.errorprone

plugins {
    java
    id("build-logic.build-params")
}

if (!project.hasProperty("skipErrorprone") && buildParameters.enableErrorprone) {
    apply(plugin = "net.ltgt.errorprone")

    dependencies {
        "errorprone"("com.google.errorprone:error_prone_core:2.38.0")
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
