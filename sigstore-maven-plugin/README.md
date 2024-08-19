[![Maven Central](https://img.shields.io/maven-central/v/dev.sigstore/sigstore-maven-plugin.svg?color&label=maven%20central)](https://central.sonatype.com/artifact/dev.sigstore/sigstore-maven-plugin)

# sigstore-maven-plugin

A Maven plugin for signing artifacts with Sigstore

Signature format uses [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) JSON as the output format.

## Minimum Requirements

* Java 11
* (optional) maven-gpg-plugin 3.2.5

## Minimal usage

```xml
      <plugin>
        <groupId>dev.sigstore</groupId>
        <artifactId>sigstore-maven-plugin</artifactId>
        <version>0.11.0</version>
        <executions>
          <execution>
            <id>sign</id>
            <goals>
              <goal>sign</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
```

### Outputs

For each file to be published an associated `<filename>.sigstore.json` signature file will be generated

### GitHub Actions OIDC support

In order for the required environment variables to be available, the workflow requires the following permissions:

```yaml
permissions:
  id-token: write
  contents: read
```

See [GitHub documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers#adding-permissions-settings) for details.


Notes:

- GPG: Maven Central publication rules require GPG signing. To avoid GPG signing of `.sigstore.json` signature files, use version 3.2.5 or higher of [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/).
- `.md5`/`.sha1`: to avoid unneeded checksum files for `.sigstore.java` files, use Maven 3.9.2 or higher, or create `.mvn/maven.config` file containing `-Daether.checksums.omitChecksumsForExtensions=.asc,.sigstore.java`

Known limitations:

- Maven multi-module build: each module will require an OIDC authentication,
- 10 minutes signing session: if a build takes more than 10 minutes, a new OIDC authentication will be required each 10 minutes.
