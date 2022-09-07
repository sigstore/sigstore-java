plugins {
    `java-library`
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
