[![Maven Central](https://maven-badges.herokuapp.com/maven-central/dev.sigstore/sigstore-java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/dev.sigstore/sigstore-java)
[![javadoc](https://javadoc.io/badge2/dev.sigstore/sigstore-java/javadoc.svg)](https://javadoc.io/doc/dev.sigstore/sigstore-java)
[![CI](https://github.com/sigstore/sigstore-java/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/sigstore/sigstore-java/actions/workflows/ci.yaml)

# sigstore-java
A sigstore java client for interacting with sigstore infrastructure

whatever, more nonsense

You can file [issues directly](https://github.com/sigstore/sigstore-java/issues) on this project or
if you have any questions message us on the [sigstore#java](https://sigstore.slack.com/archives/C03239XUL92)
slack channel

## Minimum Requirements
* Java 11

## Usage

### Build plugins

For use directly with your java build. See [maven](https://github.com/sigstore/sigstore-java/tree/main/sigstore-maven-plugin) or [gradle](https://github.com/sigstore/sigstore-java/tree/main/sigstore-gradle)
build plugin specifics.

### Keyless Signing And Verification

#### Signing
```java
Path testArtifact = Paths.get("path/to/my/file.jar")

// sign using the sigstore public instance
var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
Bundle result = signer.signFile(testArtifact);

// sigstore bundle format (serialized as <artifact>.sigstore.json)
String bundleJson = result.toJson();
```

#### Verification

##### Get artifact and bundle
```java
Path artifact = Paths.get("path/to/my-artifact");

// import a json formatted sigstore bundle
Path bundleFile = Paths.get("path/to/my-artifact.sigstore.json");
Bundle bundle = Bundle.from(bundleFile, StandardCharsets.UTF_8);
```

##### Configure verification options
```java
// add certificate policy to verify the identity of the signer
VerificationOptions options = VerificationOptions.builder().addCertificateMatchers(
  CertificateMatcher.fulcio()
    .subjectAlternativeName(StringMatcher.string("test@example.com"))
    .issuer(StringMatcher.string("https://accounts.example.com"))
    .build());
```

##### Do verification
```java
try {
  // verify using the sigstore public instance
  var verifier = new KeylessVerifier.builder().sigstorePublicDefaults().build();
  verifier.verify(artifact, bundle, verificationOptions);
  // verification passed!
} catch (KeylessVerificationException e) {
  // verification failed
}
```

### Exploring the API

The public stable API is limited to [`dev.sigstore.KeylessSigner`](https://javadoc.io/doc/dev.sigstore/sigstore-java/latest/dev/sigstore/KeylessSigner.html) and [`dev.sigstore.KeylessVerifier`](https://javadoc.io/doc/dev.sigstore/sigstore-java/latest/dev/sigstore/KeylessVerifier.html) and the classes exposed by those APIs. Other classes in the library are subject to change without notice.

You can browse Javadoc at https://javadoc.io/doc/dev.sigstore/sigstore-java.

To build and view javadoc from the sources, use the following command:

```sh
$ ./gradlew javadoc
$ "my-favorite-browser" ./sigstore-java/build/docs/javadoc/index.html
```
