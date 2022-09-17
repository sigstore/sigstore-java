plugins {
    id("dev.sigstore.sign")
}

sigstoreSign {
    oidcClient {
        gitHub()
    }
}
