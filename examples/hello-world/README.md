# Sigstore Examples

Simple sigstore signing examples

These examples sign with sigstore (and PGP as required by Maven Central)

## gradle

```
$ export ORG_GRADLE_PROJECT_signingKey=$(cat ../pgp/private.key)
$ export ORG_GRADLE_PROJECT_signingPassword=pass123

$ ./gradlew clean publishMavenPublicationToExamplesRepository

$ ls build/example-repo/com/example/hello-world/1.0.0/*.sigstore.json
hello-world-1.0.0.jar.sigstore.json
hello-world-1.0.0.modules.sigstore.json
hello-world-1.0.0.pom.sigstore.json
```

## maven

```
$ export MAVEN_GPG_KEY=$(cat ../pgp/private.key)
$ export MAVEN_GPG_PASSPHRASE=pass123

$ mvn clean deploy

$ ls target/example-repo/com/example/hello-world/1.0.0/*.sigstore.json
hello-world-1.0.0.jar.sigstore.json
hello-world-1.0.0.pom.sigstore.json
```
