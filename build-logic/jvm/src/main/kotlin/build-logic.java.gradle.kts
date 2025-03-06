import buildlogic.filterEolSimple
import com.github.vlsi.gradle.dsl.configureEach

plugins {
    `java-base`
    id("com.github.vlsi.gradle-extensions")
    id("build-logic.build-params")
    id("build-logic.spotless-base")
    id("build-logic.testing")
    id("build-logic.errorprone")
    id("build-logic.forbidden-apis")
}

java {
    toolchain {
        configureToolchain(buildParameters.buildJdk)
    }
}

tasks.configureEach<JavaExec> {
    buildParameters.testJdk?.let {
        javaLauncher.convention(javaToolchains.launcherFor(it))
    }
}

spotless {
    java {
        googleJavaFormat("1.15.0")
        licenseHeaderFile("$rootDir/config/licenseHeader")
        // Note if submodule needs to add more exclusions, it should list ALL of them since
        // Spotless does not have "addTargetExclude" method
        targetExclude("build/**/*.java")
    }
}

tasks.withType<JavaCompile>().configureEach {
    inputs.property("java.version", System.getProperty("java.version"))
    inputs.property("java.vm.version", System.getProperty("java.vm.version"))
    options.apply {
        encoding = "UTF-8"
        compilerArgs.add("-Xlint:deprecation")
        if (buildParameters.failOnJavacWarning) {
            compilerArgs.add("-Werror")
        }

        release.set(buildParameters.targetJavaVersion)
    }
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        addStringOption("sourcepath", "src/main/java")
        // intentionally ignore missing errors for now
        addBooleanOption("Xdoclint:all,-missing", true)
        if (buildParameters.failOnJavadocWarning) {
            // See JDK-8200363 (https://bugs.openjdk.java.net/browse/JDK-8200363)
            // for information about the -Xwerror option.
            addBooleanOption("Xwerror", true)
        }
    }
}

// Add default license/notice when missing (e.g. see :src:config that overrides LICENSE)

tasks.withType<Jar>().configureEach {
    into("META-INF") {
        filterEolSimple("crlf")
        from("$rootDir/LICENSE")
        from("$rootDir/NOTICE")
    }
    manifest {
        attributes["Bundle-License"] = "Apache-2.0"
        attributes["Specification-Title"] = project.name + " " + project.description
        attributes["Specification-Vendor"] = "dev.sigstore"
        attributes["Implementation-Vendor"] = "dev.sigstore"
        attributes["Implementation-Vendor-Id"] = "dev.sigstore"
        // Implementation-Version is not here to make jar reproducible across versions
    }
}
