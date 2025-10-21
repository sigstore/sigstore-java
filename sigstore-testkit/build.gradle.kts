plugins {
    id("build-logic.kotlin")
    id("build-logic.repositories")
    id("build-logic.test-junit5")
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.google.code.gson:gson:2.13.2")
    implementation("com.google.guava:guava:33.5.0-jre")

    // This is different from typical "testImplementation" dependencies, because
    // testkit exposes junit5 dependencies in its API (e.g. annotations)
    api(platform("org.junit:junit-bom:5.12.2"))
    api("org.junit.jupiter:junit-jupiter-api")
    api("org.junit.jupiter:junit-jupiter-params")
    implementation("org.junit.jupiter:junit-jupiter")
    api("org.assertj:assertj-core:3.27.6")
    api(gradleTestKit())
}
