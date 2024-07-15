# Releasing

Release is done on github. Do not release from your local machine.

## Create a tag

Tag the release at the version you wish (ex `v0.5.3`), this *MUST* match the project version (`0.5.3`). See version info in [gradle.properties](gradle.properties).

## Release `sigstore-java` and `sigstore-maven-plugin`

- Use the "Release sigstore-java and sigstore-maven-plugin to Maven Central" action against the tagged version `v0.5.3'. This action builds, signs and pushes the artifacts to Maven Central.

#### Complete the release on maven central

Releasing to maven central is a **permanent** action, it cannot be reverted

Release the bundle:
1. Log into [sonatype (s01)](https://s01.oss.sonatype.org)
1. Click "Staging Repositories" on the left navbar
1. Select your artifact, "close" it to begin checks
1. After all checks have passed, "release" it
    1. If checks are failing, "drop" the bundle and fix the release process
1. Releases show up on Maven Central roughly 1-2 hours after release

## Release `sigstore-gradle-plugin` to Gradle Plugin Portal

- Use the "Release sigstore gradle plugins to Gradle Plugin Portal" action against the tagged version `v0.5.3'. This action builds, signs and pushes the artifacts to the Gradle Plugin Portal
- There is no follow up here, plugins are auto released on the plugin portal.## Reverting a failed release (Github only)

If a release build fails for any reason or the resulting artifacts are not as expected, you must clean-up
any tags or releases built during the action
1. Delete the release from [Releases](https://github.com/sigstore/sigstore-java/releases)
2. Delete the tag from [Tags](https://github.com/sigstore/sigstore-java/tags)

### Maven Central

You can try to contact support but typically releases are permanent.

### Gradle Plugin Portal

If you wish to revert a release, you must login to the portal using `sigstore-java-releasers` within 7 days to delete a release.
