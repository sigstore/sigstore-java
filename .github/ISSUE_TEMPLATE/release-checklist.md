---
name: Release Checklist
about: All the tasks required to complete a release of sigstore-java and maven/gradle plugins
title: Release v<fill in>
labels: ''
assignees: ''

---

Full release instructions are at: [RELEASING.md](/sigstore/sigstore-java/blob/main/RELEASING.md)

## Tag Release
- [ ] `v<version>`

## Publish Release
- [ ] `sigstore-java`, `sigstore-maven-plugin` to Maven Central ([action](https://github.com/sigstore/sigstore-java/actions/workflows/release-sigstore-java-from-tag.yaml))
- [ ] `sigstore-gradle-plugin` to Gradle Plugin Portal ([action](https://github.com/sigstore/sigstore-java/actions/workflows/release-sigstore-gradle-plugin-from-tag.yaml))

## Verify Releases Published
- [ ] [sigstore-java](https://repo1.maven.org/maven2/dev/sigstore/sigstore-java)
- [ ] [sigstore-maven-plugin](https://repo1.maven.org/maven2/dev/sigstore/sigstore-maven-plugin)
- [ ] sigstore-gradle-plugin [[base](https://plugins.gradle.org/plugin/dev.sigstore.sign-base)], [[sign](https://plugins.gradle.org/plugin/dev.sigstore.sign)]

## Post Release
- [ ] Update README if required
- [ ] Update versions (`./scripts/update_version.sh`)
- [ ] Update CHANGELOG.md
