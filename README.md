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
var result = signer.sign(testArtifact);

// resulting signature information
String digest = result.getDigest(); // hex encoded sha256 digest
byte[] digestBytes = Hex.decode(result.getDigest()); // converted to byte array

CertPath certs = result.getCertPath() // java representation of a certificate path
byte[] certsBytes = Certificates.toPemBytes(result.getCertPath()) // converted to PEM encoded byte array

byte[] sig = result.getSignature() // artifact signature
```

#### Verification
```java
byte[] digest = // byte array sha256 artifact digest
byte[] certificateChain = // byte array of PEM encoded cert chain
byte[] signature = // byte array of artifact signature

try {
  var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
  verifier.verifyOnline(digest, certificateChain, signature)
} catch (KeylessVerificationException) {
  // verification failed
}

// verification passed!
```

### Exploring the API

You could browse Javadoc at https://javadoc.io/doc/dev.sigstore/sigstore-java.

To build javadoc from the sources, use the following command:

```sh
$ ./gradlew javadoc
$ "my-favorite-browser" ./sigstore-java/build/docs/javadoc/index.html
```
