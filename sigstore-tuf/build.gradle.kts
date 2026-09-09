plugins {
    id("build-logic.java-published-library")
    id("build-logic.test-junit5")
}

description = "The Update Framework (TUF) client implementation for Sigstore Java"

tasks.jar {
    manifest {
        attributes["Automatic-Module-Name"] = "dev.sigstore.tuf"
    }
}

dependencies {
    compileOnly("org.immutables:gson:2.12.2")
    compileOnly("org.immutables:value-annotations:2.12.2")
    annotationProcessor("org.immutables:value:2.12.2")

    api(project(":sigstore-common"))

    implementation("org.bouncycastle:bcutil-jdk18on:1.85")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.85")
    implementation("com.google.guava:guava:33.7.1-jre")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation(platform("org.mockito:mockito-bom:5.23.0"))
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")

    testImplementation("com.squareup.okhttp3:mockwebserver:5.5.0")
    testImplementation("io.github.netmikey.logunit:logunit-core:2.0.0")
    testRuntimeOnly("io.github.netmikey.logunit:logunit-jul:2.0.0")
    testImplementation("org.hamcrest:hamcrest:3.0")
    testImplementation("org.apache.commons:commons-lang3:3.17.0")
    testImplementation("commons-io:commons-io:2.18.0")
    testImplementation("org.jetbrains:annotations:26.0.2")
}

forbiddenApis {
    signaturesFiles = files("$rootDir/config/forbiddenApis.txt")
    suppressAnnotations = setOf("dev.sigstore.common.forbidden.SuppressForbidden")
    ignoreSignaturesOfMissingClasses = true
}
