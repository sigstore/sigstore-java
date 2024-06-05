[![Maven Central](https://maven-badges.herokuapp.com/maven-central/dev.sigstore/sigstore-java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/dev.sigstore/sigstore-java)
[![javadoc](https://javadoc.io/badge2/dev.sigstore/sigstore-java/javadoc.svg)](https://javadoc.io/doc/dev.sigstore/sigstore-java)
[![CI](https://github.com/sigstore/sigstore-java/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/sigstore/sigstore-java/actions/workflows/ci.yaml)

# sigstore-java
A sigstore java client for interacting with sigstore infrastructure

⚠️ This project is not ready for general-purpose use! ⚠️

This project requires a minimum of Java 11 and is current in pre-release,
apis and dependencies are likely to change

You can files issues directly on this project or if you have any questions
message us on the [sigstore#java](https://sigstore.slack.com/archives/C03239XUL92) slack channel

## Usage

### Keyless Signing And Verification

#### Signing
```java
Path testArtifact = Paths.get("path/to/my/file.jar")

var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
Bundle result = signer.signFile(testArtifact);

// sigstore bundle format (serialized as <artifact>.sigstore.json)
String bundleJson = result.toJson();
```

#### Verification

##### Read bundle
```java
Path bundleFile = // java.nio.Path to a .sigstore.json signature bundle file
Bundle bundle = Bundle.from(Files.newBufferedReader(bundleFile, StandardCharsets.UTF_8));
```

##### Configure verification options
```java
// add certificate policy to verify the identity of the signer
VerificationOptions verificationOptions =
    VerificationOptions.builder()
        .addCertificateIdentities(
            CertificateIdentity.builder()
                .issuer("https://accounts.example.com"))
                .subjectAlternativeName("test@example.com")
                .build())
        .build();
```

##### Do verification
```java
Path artifact = // java.nio.Path to artifact file
try {
  var verifier = new KeylessVerifier.builder().sigstorePublicDefaults().build();
  verifier.verify(artifact, bundle, verificationOptions);
  // verification passed!
} catch (KeylessVerificationException e) {
  // verification failed
}
```

### Exploring the API

The public stable API is limited to `dev.sigstore.KeylessSigner`(https://javadoc.io/doc/dev.sigstore/sigstore-java/latest/dev/sigstore/KeylessSigner.html) and `dev.sigstore.KeylessVerifier`(https://javadoc.io/doc/dev.sigstore/sigstore-java/latest/dev/sigstore/KeylessVerifier.html) and the classes exposed by those APIs. Other classes in the library are subject to change without notice.

You can browse Javadoc at https://javadoc.io/doc/dev.sigstore/sigstore-java.

To build javadoc from the sources, use the following command:

```sh
$ ./gradlew javadoc
$ "my-favorite-browser" ./sigstore-java/build/docs/javadoc/index.html
```
