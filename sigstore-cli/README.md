# Sigstore-Java CLI

Used for conformance testing and internal processes. This is not meant for public consumption, we will not support
any usecase that uses this.

## Usage

### Help
```
./gradlew sigstore-cli:run
```

### Sign

#### bundle
```
./gradlew sigstore-cli:run --args="sign --bundle=bundle.json <artifact>"
```

#### separate cert and sig files
```
./gradlew sigstore-cli:run --args="sign --certificate=cert.pem --signature=sig <artifact>"
```

### Verify

#### bundle
```
./gradlew sigstore-cli:run --args="verify --bundle=bundle.json <artifact>"
```

#### separate cert and sig files
```
./gradlew sigstore-cli:run --args="verify --certificate=cert.pem --signature=sig <artifact>"
```

#### verify with policy
```
./gradlew sigstore-cli:run --args="verify <...> --certificate-identity="goose@example.com" --certificate-oidc-issuer="https://accounts.example.com" <artifact>"
```
