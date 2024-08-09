# Sigstore Examples

Simple sigstore signing examples

## gradle

```
$ ./gradlew clean publishMavenPublicationToExamplesRepository

$ ls build/example-repo/com/example/hello-world/1.0.0/*.sigstore.json
hellow-world-1.0.0.jar.sigstore.json
hellow-world-1.0.0.modules.sigstore.json
hellow-world-1.0.0.pom.sigstore.json
```

## maven

```
$ mvn clean deploy

$ ls target/example-repo/com/example/hello-world/1.0.0/*.sigstore.json
hello-world-1.0.0.jar.sigstore.json
hello-world-1.0.0.pom.sigstore.json
```
