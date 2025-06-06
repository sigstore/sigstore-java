[![Gradle Plugin Portal](https://img.shields.io/maven-metadata/v/https/plugins.gradle.org/m2/dev/sigstore/sigstore-gradle-sign-plugin/maven-metadata.xml.svg?color&label=gradle%20plugin%20portal)](https://plugins.gradle.org/plugin/dev.sigstore.sign/)

# sigstore-gradle

A Gradle plugin for signing artifacts with Sigstore.

Signature format uses [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) JSON as the output format.

## Minimum Requirements

* Java 11
* Gradle 7.5

## Minimal usage

```kotlin
plugins {
    id("dev.sigstore.sign") version "1.3.0"
}

// Automatically sign all Maven publications, using GitHub Actions OIDC when available,
// and browser based OIDC otherwise.
```

### Outputs

For each file to be published an associated `<filename>.sigstore.json` signature file will be generated

### GitHub Actions OIDC support

In order for the required environment variables to be available, the workflow requires the following permissions:

```yaml
permissions:
  id-token: write
  contents: read
```

See [GitHub documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers#adding-permissions-settings) for details.


## Full configuration

```kotlin
plugins {
    id("dev.sigstore.sign")
}

dependencies {
    // Override sigstore-java clients
    sigstoreClient("dev.sigstore:sigstore-java:<alternate-version>")
}

sigstoreSign {
    oidcClient {
        // oidcClient configuration should very rarely be configured, it should be
        // inferred from a sigstore deployment's config obtained from a TUF repository
        // with a default set of ambient credential providers
        gitHub {
            audience.set("sigstore")
        }
        web {
            clientId.set("sigstore")
            issuer.set("https://oauth2.sigstore.dev/auth")
        }
        // override the client config to a specific provider
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

The signature uses [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) JSON
stored as `.sigstore.json` file.

The file includes all the information for offline signature verification.

### dev.sigstore.sign plugin

Automatically signs all Maven publications in Sigstore.

### dev.sigstore.sign-base plugin

Provides `SigstoreSignFilesTask` task for signing files in Sigstore.
The plugin adds no tasks by default.

Properties:
* `dev.sigstore.sign.remove.sigstore.json.asc` (since 0.6.0, default: `true`). Removes `.sigstore.json.asc` files from the publication.
  Sonatype OSSRH supports publishing `.sigstore.json` signatures, and it does not require `.sigstore.json.asc` files, so
  `dev.sigstore.sign` plugin removes them by default. If you need to sign all the files, set this property to `false`.

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


