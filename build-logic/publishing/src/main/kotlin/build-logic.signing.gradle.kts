plugins {
    id("signing")
    id("dev.sigstore.sign")
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
}

tasks.withType<Sign>().configureEach {
    onlyIf("Is a release") {
        project.hasProperty("release")
    }
    onlyIf("Signing is not skipped") {
        !project.hasProperty("skipSigning")
    }
    onlyIf("PGP Signing is not skipped") {
        !project.hasProperty("skipPgpSigning")
    }
}

tasks.withType<dev.sigstore.sign.tasks.SigstoreSignFilesTask>().configureEach {
    onlyIf("Is a release") {
        project.hasProperty("release")
    }
    onlyIf("Signing is not skipped") {
        !project.hasProperty("skipSigning")
    }
    onlyIf("Sigstore Signing is not skipped") {
        !project.hasProperty("skipSigstoreSigning")
    }
}
