# TUF Store

This resource is a temporary alternative to an actual TUF client.
This is **not a permanent solution** and should not be treated as such.
If the key changes, they will not automatically be reflected here
and various signing/verification workflows will fail.

We keep copies of the remote tuf repositories locally in
1. Production from https://storage.googleapis.com/sigstore-tuf-root \
   for interfacing with *.sigstore.dev

2. Staging from https://storage.googleapis.com/tuf-root-staging \
   for interfacing with *.sigstage.dev

For this client to function we need the following keys
1. CTFE public key (`ctfe.pub` \
   the public key for the certificate transparency log
2. Fulcio root cert (`fulcio_v1.crt.pem` or `fulcio.crt.pem`)\
   the root certificate for fulcio issued certificates
3. Rekor public key (`rekor.pub`) \
   the public key for the rekor transparency log
