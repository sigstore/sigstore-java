These test keys were creating using the following commands:

**test-ec.pub** - actually this was copied from [here](https://github.com/sigstore/sigstore-java/blob/main/src/test/resources/dev/sigstore/samples/fulcio-response/valid/ctfe.pub).

**test-rsa.pub**
```
`step crypto keypair ctfe-rsa.pub tmp.key -kty RSA --no-password --insecure
```

**test-ed25519.pub**
```
`step crypto keypair ctfe-ed25519.pub tmp.key -kty OKP --curve Ed25519 --no-password --insecure
```

**test-dsa.pub**
```
ssh-keygen -t dsa -f test-dsa   
ssh-keygen -f test-dsa.pub -e -m pem > test-dsa.pub.pem
```