# Plumbing the sigstore trustroot through sigstore-java

https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json

The trust root should be the mechanism by which we initialize all our clients.
Values will be inferred from the trustroot when initializing the client. Signing and verifying
have slightly different requirements, but the way our trusted_root.json is constructed means
it should satisfy the conditions for both signing and verifying.

### Signing
For signing we require *exactly one* current active reference to:
1. certificate authority (fulcio)
1. ct log (fulcio)
1. transparency log (rekor)

A signer only needs to interface with current infrastructure both for generating and storing signatures and validating the results during signing.
Old infrastucture references are not requires at signing time.

### Verification

#### Initialize for Cyrptographic Checks
1. We initialize the verifiers with all available keys/certificates. This allows us to instantiate single verifiers for cryptographic checks. We can populate this by querying the trustroot for all CAs and CTLogs (FulcioVerifier) and TLogs (RekorVerifier).

#### Additional verification checks
Since we rotate keys and certificates with validity periods defined in the trust root, for a given bundle (signature, certificate, tlog entry), we need
1. certificate authorities that were active when the certificate was issued
1. ct logs that were active when the SCT in the certificate was issued
1. rekor instances that were active when the tlog entry was created

Verication can occur against verification material from the entire history of sigstore (unless there's some deprecation period - there isn't yet?),
so we need to search through and find valid infrastructure pieces for when the signing event occurred.

## trusted_root accessors api
To obtain the appropriate material the trust root needs to be able to
1. Obtain all CA, CTlogs and Tlogs to initialize our generic verification mechanisms
    - Our generic verifiers should be able to verify the cyptographic correctness of things without worrying about the sigstore
      specific time constraints on verification material.
1. Filter CAs by time
    - There are some additional calculations to determine if a CA has provided the cert that is not done by the trusted_root, it is a simple filter.
      The code reponsible for verifying a cert, must pick from a time filter list of CAs the appropriate CA to verify against.
1. Filter CTlogs and Tlogs by time and logId
    - This should always narrow down verification of log entries to a single log.
    - logId for CTlogss is always the sha256 of the public key. (we can verify or fail here)
    - logId for Tlogs is provided in the bundle. (Not preferrable, but this may also be reconstructed from the signing materials and checked against all logs
      in the trusted_root).
