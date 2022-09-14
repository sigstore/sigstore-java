## build and test
```sh
./gradlew build
```

## skip tests that require OIDC logins

```sh
./gradlew build -PskipOidc
```

## apply automatic formatting
```sh
./gradlew spotlessApply
```

## install into local maven repo
```sh
./gradlew publishToMavenLocal
```
