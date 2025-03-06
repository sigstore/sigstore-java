plugins {
    id("org.gradlex.build-parameters") version "1.4.4"
    id("build-logic.kotlin-dsl-gradle-plugin")
}

buildParameters {
    // Other plugins can contribute parameters, so below list is not exhaustive
    enableValidation.set(false)
    pluginId("build-logic.build-params")
    integer("targetJavaVersion") {
        defaultValue.set(11)
        mandatory.set(true)
        description.set("Java version for source and target compatibility")
    }
    val projectName = "sigstore-java"
    integer("jdkBuildVersion") {
        defaultValue.set(17)
        mandatory.set(true)
        description.set("JDK version to use for building $projectName. If the value is 0, then the current Java is used. (see https://docs.gradle.org/8.4/userguide/toolchains.html#sec:consuming)")
    }
    string("jdkBuildVendor") {
        description.set("JDK vendor to use building $projectName (see https://docs.gradle.org/8.4/userguide/toolchains.html#sec:vendors)")
    }
    string("jdkBuildImplementation") {
        description.set("Vendor-specific virtual machine implementation to use building $projectName (see https://docs.gradle.org/8.4/userguide/toolchains.html#selecting_toolchains_by_virtual_machine_implementation)")
    }
    integer("jdkTestVersion") {
        description.set("JDK version to use for testing $projectName. If the value is 0, then the current Java is used. (see https://docs.gradle.org/current/userguide/toolchains.html#sec:vendors)")
    }
    string("jdkTestVendor") {
        description.set("JDK vendor to use testing $projectName (see https://docs.gradle.org/8.4/userguide/toolchains.html#sec:vendors)")
    }
    string("jdkTestImplementation") {
        description.set("Vendor-specific virtual machine implementation to use testing $projectName (see https://docs.gradle.org/8.4/userguide/toolchains.html#selecting_toolchains_by_virtual_machine_implementation)")
    }
    bool("enableErrorprone") {
        defaultValue.set(false)
        description.set("Run ErrorProne verifications")
    }
    bool("skipForbiddenApis") {
        defaultValue.set(false)
        description.set("Skip forbidden-apis verifications")
    }
    bool("skipJavadoc") {
        defaultValue.set(false)
        description.set("Skip javadoc generation")
    }
    bool("failOnJavadocWarning") {
        defaultValue.set(true)
        description.set("Fail build on javadoc warnings")
    }
    bool("failOnJavacWarning") {
        defaultValue.set(true)
        description.set("Fail build on javac warnings")
    }
}
