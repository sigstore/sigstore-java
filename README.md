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

// artifact digest
byte[] digest = result.getDigest();

// certificate from fulcio
CertPath certs = result.getCertPath() // java representation of a certificate path
byte[] certsBytes = Certificates.toPemBytes(result.getCertPath()) // converted to PEM encoded byte array

// artifact signature
byte[] sig = result.getSignature()

// sigstore bundle format (json string)
String bundle = BundleFactory.createBundle(result)
```

#### Verification

##### KeylessSignature from certificate and signature
```java
byte[] digest = // byte array sha256 artifact digest
byte[] certificateChain = // byte array of PEM encoded cert chain
byte[] signature = // byte array of artifact signature
var keylessSignature = 
    KeylessSignature.builder()
        .signature(signature)
        .certPath(Certificates.fromPemChain(certPath))
        .digest(digest)
        .build();
```

##### KeylessSignature from bundle
```java
var bundleFile = // java.nio.path to some bundle file
var keylessSignature = BundleFactory.readBundle(Files.newBufferedReader(bundleFile, StandardCharsets.UTF_8));
```

##### Configure verification options
```java
var verificationOptions = 
    VerificationOptions.builder()
        // verify online? (connect to rekor for inclusion proof)
        .isOnline(true)
        // optionally add certificate policy
        .addCertificateIdentities(
            CertificateIdentity.builder()
                .issuer("https://accounts.example.com"))
                .subjectAlternativeName("test@example.com")
                .build())
        .build();
```

##### Do verification
```java
var artifact = // path to artifact file
try {
  var verifier = new KeylessVerifier.Builder().sigstorePublicDefaults().build();
  verifier.verify(
      artifact,
      KeylessVerificationRequest.builder()
          .keylessSignature(keylessSignature)
          .verificationOptions(verificationOptions)
          .build());
  // verification passed!
} catch (KeylessVerificationException e) {
  // verification failed
}
```

### Exploring the API

You could browse Javadoc at https://javadoc.io/doc/dev.sigstore/sigstore-java.

To build javadoc from the sources, use the following command:

```sh
$ ./gradlew javadoc
$ "my-favorite-browser" ./sigstore-java/build/docs/javadoc/index.html
```
