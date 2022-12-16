plugins {
    `java-library`
    id("build-logic.testing")
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testImplementation("org.assertj:assertj-core")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
