plugins {
    id("build-logic.java")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":sigstore-java"))
    implementation("com.code-intelligence:jazzer-api:0.16.1")
    implementation("com.google.code.gson:gson:2.8.9")
    implementation("com.google.guava:guava:31.1-jre")
    implementation("com.squareup.okhttp3:mockwebserver:4.9.3")
    implementation("no.nav.security:mock-oauth2-server:0.5.8")

    implementation(platform("io.grpc:grpc-bom:1.46.0"))
    implementation("io.grpc:grpc-protobuf")
}

// copy to the fuzzing builder's output directory. This is an existing directory with
// files in it, so don't use sync
tasks.register<Copy>("copyToFuzzOut") {
    dependsOn(tasks.build)
    into(project.findProperty("fuzzOut") ?: project.layout.buildDirectory.dir("fuzzOut"))
    from(sourceSets.main.get().runtimeClasspath)
    from(project(":sigstore-java").layout.projectDirectory.dir("src/test/resources/dev/sigstore/oidc/server/config.json"))
    rename("config.json", "oidc-config.json")
}
