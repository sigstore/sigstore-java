# Sigstore Gradle plugin samples

## Samples

* [Sign Java Library](gradle-sign-java-library)
  Shows the way to configure sigstore signing.

  Try running `./gradlew :gradle-sign-java-library:publishAllPublicationsToTmpRepository`
  The output will be put into `gradle-sign-java-library/build/tmp-repo`

* [Sign file](gradle-sign-file)
  Shows the way to sign a single file via Gradle task.

  Try running `./gradlew :gradle-sign-file:signFile`.
  The output will be put into `gradle-sign-file/build/sigstore/signFile`
