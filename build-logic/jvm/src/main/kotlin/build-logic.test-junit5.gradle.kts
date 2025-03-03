plugins {
    `java-library`
    id("build-logic.testing")
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher") {
        because("It is needed for junit in runtime, see https://github.com/junit-team/junit5/issues/4335#issuecomment-2676780444")
    }
    testImplementation("org.assertj:assertj-core")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
