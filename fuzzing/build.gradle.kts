plugins {
    id("build-logic.java")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.code-intelligence:jazzer-api:0.16.0")
}

tasks.register<Copy>("copyToFuzzOut") {
    dependsOn(tasks.build)
    into(project.property("fuzzOut")).from(sourceSets.main.get().runtimeClasspath)
}
