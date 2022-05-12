# sigstore-java
A sigstore java client for interacting with sigstore infrastructure

Minimum Java 8

This is a WIP, currently consists of

### fulcio client

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
SigningCertificate signingCert = fulcioClient.SigningCert(cReq, idToken);

// sign something with our private key, throw it away and save the cert with the artifact
```

### oidc client

```
OidcClient oidcClient = OidcClient.builder().build();

EmailIdToken eid = oidcClient.getIDToken(null);

// email address, to sign and use when creating a CertificateRequest for fulcio
eid.getEmailAddress();
// idToken, to use when making a call to FulcioClient#SigningCert
eid.getIdToken();

```

To be added
- rekor client

Maybe to be added here or somewhere else
- signer
- java tuf client (might be useful outside of the sigstore ecosystem)
