#!/usr/bin/env bash
set -Eeo pipefail
export MAVEN_GPG_KEY=$(cat ../pgp/private.key)
export MAVEN_GPG_PASSPHRASE=pass123
export ORG_GRADLE_PROJECT_signingKey=$MAVEN_GPG_KEY
export ORG_GRADLE_PROJECT_signingPassword=$MAVEN_GPG_PASSPHRASE
set -x
# gradle
./gradlew clean publishMavenPublicationToExamplesRepository --stacktrace $@
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.jar.sigstore.json
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.module.sigstore.json
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.pom.sigstore.json
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.jar.asc
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.module.asc
test -f build/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.pom.asc
# maven
mvn clean deploy --no-transfer-progress $@
test -f target/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.jar.sigstore.json
test -f target/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.pom.sigstore.json
test -f target/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.jar.asc
test -f target/example-repo/com/example/hello-world/1.0.0/hello-world-1.0.0.pom.asc
# ensure no double signed (pgp and sigstore) files
test $(find . -name "*.asc.sigstore.java" | wc -c) -eq 0
test $(find . -name "*.sigstore.java.asc" | wc -c) -eq 0
