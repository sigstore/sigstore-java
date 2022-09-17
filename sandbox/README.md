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

* [Precompiled plugin](gradle-precompiled-plugin)
  Shows the way `dev.sigstore.sign` can be a part of a
  [precompiled script plugin](https://docs.gradle.org/current/userguide/custom_plugins.html#sec:precompiled_plugins).
