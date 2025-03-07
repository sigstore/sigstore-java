## build and test
```sh
./gradlew build
```

## execute tests with Java 23 
```sh
./gradlew build -PjdkTestVersion=23
```

# list build parameters

```sh
./gradlew parameters
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

## build OSS-Fuzz set up
```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_fuzzers sigstore-java

# Fuzzers are now in `build/out/sigstore-java`
# To e.g. run e.g. CertificatesFuzzer
python3 infra/helper.py run_fuzzer sigstore-java CertificatesFuzzer
```

## build OSS-Fuzz set up with local sigstore-java code
```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_fuzzers sigstore-java PATH_TO_LOCAL_REPO
```

## browse all sigstore-java issues
https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Dsigstore-java&can=1

To see private issues (e.g. issues within disclosure deadline) your email must
be in the OSS-Fuzz [project.yaml](https://github.com/google/oss-fuzz/blob/master/projects/sigstore-java/project.yaml).


## reproduce OSS-Fuzz crash
Assuming you have a testcase from a fuzzer issue at path TESTCASE_PATH
and the fuzzer that triggered the issue is FUZZER_NAME then the following
steps will reproduce the issue:
```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_fuzzers sigstore-java
python3 infra/helper.py reproduce sigstore-java FUZZER_NAME TESTCASE_PATH
```
