# sigstore-java
A sigstore java client for interacting with sigstore infrastructure

This project requires a minimum of Java 11 and is current in pre-release,
apis and dependnecies are likely to change

You can files issues directly on this project or if you have any questions
message us on the [sigstore#java](https://sigstore.slack.com/archives/C03239XUL92) slack channel

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

We do not have a process yet for publishing javadocs, but you can checkout the code
at master (or a tagged version) and run

```
$ ./gradlew javadoc
$ "my-favorite-browser" ./build/docs/javadoc/index.html
```
