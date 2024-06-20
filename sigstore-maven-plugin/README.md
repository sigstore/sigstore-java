sigstore-maven-plugin
=====================

[![Maven Central](https://img.shields.io/maven-central/v/dev.sigstore/sigstore-maven-plugin.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/dev.sigstore/sigstore-maven-plugin)

This is a Maven plugin that can be used to use the "keyless" signing paradigm supported by Sigstore.
This plugin is still in early phases, then has known limitations described below.

sign
----

```xml
      <plugin>
        <groupId>dev.sigstore</groupId>
        <artifactId>sigstore-maven-plugin</artifactId>
        <version>0.4.0</version>
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

Notes:

- GPG: Maven Central publication rules require GPG signing each files: to avoid GPG signing of `.sigstore.json` files, just use version 3.1.0 minimum of [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/).
- `.md5`/`.sha1`: to avoid unneeded checksum files for `.sigstore.java` files, use Maven 3.9.2 minimum or create `.mvn/maven.config` file containing `-Daether.checksums.omitChecksumsForExtensions=.asc,.sigstore.java`

Known limitations:

- Maven multi-module build: each module will require an OIDC authentication,
- 10 minutes signing session: if a build takes more than 10 minutes, a new OIDC authentication will be required each 10 minutes.
