## sigstore-gradle

A Gradle plugin for signing artifacts with Sigstore.

## The current state

`dev.sigstore.sign` has no releases yet.
Signature format uses [Sigstore bundle](https://github.com/sigstore/cosign/pull/2204) JSON which is still experimental.

## Requirements

Java 11 (https://github.com/sigstore/sigstore-java requires Java 11)
Gradle 7.5 (Gradle 6 could be supported once https://github.com/jsonschema2dataclass/js2d-gradle/issues/401 is released)
Gradle configuration cache is supported.

## Minimal usage

```kotlin
plugins {
    id("dev.sigstore.sign")
}

// It would automatically sign all Maven publications
// By default, it would use GitHub Actions OIDC when available,
// and it would resort to Web Browser OIDC otherwise.
```

## Full configuration

```kotlin
plugins {
    id("dev.sigstore.sign")
}

dependencies {
    // Override sigstore-java clients
    sigstoreClient("dev.sigstore:sigstore-java:0.1.0")
}

sigstoreSign {
    oidcClient {
        gitHub {
            audience.set("sigstore")
        }
        web {
            clientId.set("sigstore")
            issuer.set("https://oauth2.sigstore.dev/auth")
        }
        // By default, gitHub client is used if ACTIONS_ID_TOKEN_REQUEST_URL environment variable exists
        // This setting would enforce web OIDC client
        client.set(web)
        // or
        client(web)
    }
}
```

## How to

### Sign Maven publications

```kotlin
plugins {
    id("dev.sigstore.sign")
}
// Default configuration signs Maven publications
```

### Skip signing Maven publications

If you want to avoid automatic signing, consider using `dev.sigstore.sign-base` plugin:

```kotlin
plugins {
    id("dev.sigstore.sign-base")
}

// Configure SigstoreSignFilesTask tasks as you need
```

### Sign a single file

```kotlin
plugins {
    id("dev.sigstore.sign-base")
}

dev.sigstore.sign.tasks.SigstoreSignFilesTask

val helloProps by tasks.registering(WriteProperties::class) {
    outputFile = file("build/helloProps.txt")
    property("helloProps", "world")
}

val signHelloProps by tasks.registering(SigstoreSignFilesTask::class) {
    // outputFile is File, so helloProps.map {..} is Provider<File>
    signFile(helloProps.map { it.outputFile })
    // Alternative APIs are
    // sign(File)
    // sign(Provider<RegularFile>)
}

val zip by tasks.registering(Zip::class) {
    from(signHelloProps.map { it.singleSignature() })
}
```

## Technical details

### Signature format

The signature uses [Sigstore bundle](https://github.com/sigstore/cosign/pull/2204) JSON
stored as `.sigstore` file.

The file includes all the information for offline signature verification.

### dev.sigstore.sign plugin

Automatically signs all Maven publications in Sigstore.

### dev.sigstore.sign-base plugin

Provides `SigstoreSignFilesTask` task for signing files in Sigstore.
The plugin adds no tasks by default.

Extensions:
* `sigstoreSign`: `dev.sigstore.sign.SigstoreSignExtension`

  Configures signing parameters

  * `oidcClient`: `dev.sigstore.sign.OidcClientExtension`

    Configures OIDC token source.

    Supported sources: web browser, GitHub Actions.

Configurations:
* `sigstoreClient`

  A configuration to declare the version for `sigstore-java`.

* `sigstoreClientClasspath`

  A configuration that resolves `sigstore-java` dependencies.

Tasks:

* `dev.sigstore.sign.SigstoreSignFilesTask`

  Signs entries via Sigstore.


