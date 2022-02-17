# sigstore-java
A sigstore java client for interacting with sigstore infrastructure

Minimum Java 8

This is a WIP, currently only consists
- fulcio client

```java
// pre-requisites
String subject // email of signer
String idToken // idtoken from OIDC server for email

// create a new client
Client fulcioClient = Client.Builder().setServerUrl("my fulcio url").build();

// create an ECDSA p-256 keypair, this is our key that we want to generate certs for
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
keyGen.initialize(256);
KeyPair keys = keyGen.generateKeyPair();

// sign the "subject" with our key, this signer already generates asn1 notation
Signature signature = Signature.getInstance("SHA256withECDSA");
signature.initSign(keys.getPrivate());
signature.update(subject.getBytes(StandardCharsets.UTF_8));
byte[] signed = signature.sign();

// create a certificate request with our public key and our signed "subject"
CertificateRequest cReq = new CertificateRequest(keys.getPublic(), signed);

// ask fulcio for a signing cert chain for our public key
CertificateResponse cResp = fulcioClient.SigningCert(cReq, token);

// sign something with our private key, throw it away and save the cert with the artifact
```

To be added
- rekor client
- dex/oidc client

Maybe to be added here or somewhere else
- signer
- java tuf client (might be useful outside of the sigstore ecosystem)
