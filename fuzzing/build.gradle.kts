plugins {
    id("build-logic.java")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.code-intelligence:jazzer-api:0.24.0")
    implementation("com.google.guava:guava:33.4.8-jre")
}

// copy to the fuzzing builder's output directory. This is an existing directory with
// files in it, so don't use sync
tasks.register<Copy>("copyToFuzzOut") {
    dependsOn(tasks.build)
    into(project.findProperty("fuzzOut") ?: project.layout.buildDirectory.dir("fuzzOut"))
    from(sourceSets.main.get().runtimeClasspath)
}
