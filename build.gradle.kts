// codeql java version hint: languageVersion = JavaLanguageVersion.of(21)
// https://github.com/github/codeql-action/issues/1855

plugins {
    id("build-logic.root-build")
    id("com.gradleup.nmcp.aggregation") version "1.4.4"
    // The Kotlin Gradle plugin was loaded multiple times in different subprojects, which is not supported and may break the build.
    `embedded-kotlin` apply false
}

val calculatedVersion = property("version") as String + (if (hasProperty("release")) "" else "-SNAPSHOT")

allprojects {
    version = calculatedVersion
}

val parameters by tasks.registering {
    group = HelpTasksPlugin.HELP_GROUP
    description = "Displays build parameters (i.e. -P flags) that can be used to customize the build"
    dependsOn(gradle.includedBuild("build-logic").task(":build-parameters:parameters"))
}

nmcpAggregation {
    centralPortal {
        username = providers.environmentVariable("CENTRAL_PORTAL_USERNAME")
        password = providers.environmentVariable("CENTRAL_PORTAL_PASSWORD")
        publishingType = "USER_MANAGED"
        publicationName = "sigstore java $version"
    }
}

dependencies {
    nmcpAggregation(project(":sigstore-java"))
    nmcpAggregation(project(":sigstore-maven-plugin"))
}
