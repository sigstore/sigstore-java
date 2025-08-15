# Releasing

Release is done on github. Do not release from your local machine.

## Create an issue

Create a release issue using the release template

## Create a tag

Tag the release at the version you wish (ex `v0.5.3`), this *MUST* match the project version (`0.5.3`). See version info in [gradle.properties](gradle.properties).

## Release `sigstore-java` and `sigstore-maven-plugin`

- Use the "Release sigstore-java and sigstore-maven-plugin to Maven Central" action against the tagged version `v0.5.3'. This action builds, signs and pushes the artifacts to Maven Central.

#### Complete the release on maven central

Releasing to maven central is a **permanent** action, it cannot be reverted

Release the bundle:
1. Log into [maven central](https://central.sonatype.org)
1. Click on your account icon in the top right and then "View Deployments" ([link](https://central.sonatype.com/publishing/deployments))
1. Select your Deployment, wait for it to finish validation and then "Publish" it
1. Releases show up on Maven Central roughly 0-2 hours after release

## Release `sigstore-gradle-plugin` to Gradle Plugin Portal

- Use the "Release sigstore gradle plugins to Gradle Plugin Portal" action against the tagged version `v0.5.3'. This action builds, signs and pushes the artifacts to the Gradle Plugin Portal
- There is no follow up here, plugins are auto released on the plugin portal.## Reverting a failed release (Github only)

## Revert a Release
If a release build fails for any reason or the resulting artifacts are not as expected, you must clean-up
any tags or releases built during the action
1. Delete the release from [Releases](https://github.com/sigstore/sigstore-java/releases)
2. Delete the tag from [Tags](https://github.com/sigstore/sigstore-java/tags)

### Maven Central

If you accidentally publish something to maven central you didn't want to, you can try to contact support but typically releases are permanent.

### Gradle Plugin Portal

If you wish to revert a release, you must login to the portal using `sigstore-java-releasers` within 7 days to delete a release.
