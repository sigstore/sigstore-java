import buildlogic.filterEolSimple

plugins {
    `java-base`
    id("com.github.vlsi.gradle-extensions")
    id("build-logic.spotless-base")
    id("build-logic.testing")
    id("build-logic.errorprone")
    id("build-logic.forbidden-apis")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
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
        compilerArgs.add("-Werror")
    }
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("Xwerror", true)
        addStringOption("sourcepath", "src/main/java")
        // intentionally ignore missing errors for now
        addBooleanOption("Xdoclint:all,-missing", true)
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
