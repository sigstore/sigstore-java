plugins {
    id("build-logic.kotlin")
    id("build-logic.repositories")
}

dependencies {
    api(platform("org.junit:junit-bom:5.9.0"))
    api("org.junit.jupiter:junit-jupiter")
    api("org.assertj:assertj-core:3.23.1")
    api(gradleTestKit())
}
