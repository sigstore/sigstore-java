plugins {
    id("build-logic.kotlin")
    id("build-logic.repositories")
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.google.code.gson:gson:2.9.1")
    implementation("com.google.guava:guava:31.1-jre")

    api(platform("org.junit:junit-bom:5.9.0"))
    api("org.junit.jupiter:junit-jupiter")
    api("org.assertj:assertj-core:3.23.1")
    api(gradleTestKit())
}
