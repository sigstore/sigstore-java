plugins {
    id("build-logic.java")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.code-intelligence:jazzer-api:0.23.0")
    implementation("com.google.guava:guava:33.3.1-jre")
}

// copy to the fuzzing builder's output directory. This is an existing directory with
// files in it, so don't use sync
tasks.register<Copy>("copyToFuzzOut") {
    dependsOn(tasks.build)
    into(project.findProperty("fuzzOut") ?: project.layout.buildDirectory.dir("fuzzOut"))
    from(sourceSets.main.get().runtimeClasspath)
}
