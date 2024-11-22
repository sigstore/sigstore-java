# Changelog

All notable changes to `sigstore-java` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 1.0.0 are untracked


## [Unreleased]

# [1.1.0] - 2024-11-22

## Added
- Update sigstore tuf roots to v10 for staging and public-good https://github.com/sigstore/sigstore-java/pull/848
- Tuf conformance tests for tuf client spec conformance https://github.com/sigstore/sigstore-java/pull/838

## Changed
- Allow tuf updater to fetch meta without downloading targets https://github.com/sigstore/sigstore-java/pull/839
- Allow tuf targets and metadata to be stored and fetched separately https://github.com/sigstore/sigstore-java/pull/827

## Fixed
- Fix handling of tuf targets in subdirectories https://github.com/sigstore/sigstore-java/pull/853
- Fix tuf spec conformance for valid but duplicate signatures on a role https://github.com/sigstore/sigstore-java/pull/852
- Fix handling of rsa-pss and ed25519 signatures in tuf metadata https://github.com/sigstore/sigstore-java/pull/849/files

## Security
- Ensure log entries in sigstore bundles are entries that correspond to the 
  verification material (signature, artifact, public-key) provided to the 
  verifier. https://github.com/sigstore/sigstore-java/pull/856

# [1.0.0] - 2024-08-28

## Added
- `sigstore-java`, `sigstore-maven-plugin`, `dev.sigstore.sign` (gradle) are now GA
