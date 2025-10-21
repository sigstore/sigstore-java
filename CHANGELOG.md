# Changelog

All notable changes to `sigstore-java` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 1.0.0 are untracked


## [Unreleased]

# [2.0.0-rc2] - 2025-10-21

## Fixed
- Fix TUF snapshot version rollback case: https://github.com/sigstore/sigstore-java/pull/1061
- Fix userAgent string in requests: https://github.com/sigstore/sigstore-java/pull/1066
- Handle parsing/format failures: https://github.com/sigstore/sigstore-java/pull/1063, https://github.com/sigstore/sigstore-java/pull/1064, https://github.com/sigstore/sigstore-java/pull/1073, https://github.com/sigstore/sigstore-java/pull/1074, https://github.com/sigstore/sigstore-java/pull/1075

## Changed
- Remove oidc config from gradle plugin: https://github.com/sigstore/sigstore-java/pull/1076

# [2.0.0-rc1] - 2025-08-14

## Added
- Add support for rekor v2 logs https://github.com/sigstore/sigstore-java/pull/990, https://github.com/sigstore/sigstore-java/pull/1016, https://github.com/sigstore/sigstore-java/pull/1017, https://github.com/sigstore/sigstore-java/pull/1008, https://github.com/sigstore/sigstore-java/pull/1031, https://github.com/sigstore/sigstore-java/pull/1040
- Add support for timestamps https://github.com/sigstore/sigstore-java/pull/960, https://github.com/sigstore/sigstore-java/pull/975, https://github.com/sigstore/sigstore-java/pull/977, https://github.com/sigstore/sigstore-java/pull/978, https://github.com/sigstore/sigstore-java/pull/979
- Library support for token string auth https://github.com/sigstore/sigstore-java/pull/925
- ED25519 support in trusted\_root https://github.com/sigstore/sigstore-java/pull/983

## Fixed
- Fixed windows support https://github.com/sigstore/sigstore-java/pull/974
- Parsing json with unknown fields https://github.com/sigstore/sigstore-java/pull/966

## Changed
- Users can no longer specify signer object in KeylessSigner, use Algorithm Registry instead https://github.com/sigstore/sigstore-java/pull/1027 
- Users with custom sigstore infrastructure deployments must specify a SigningConfig to configure the KeylessSigner, individual urls for infrastructure pieces are removed https://github.com/sigstore/sigstore-java/pull/956, https://github.com/sigstore/sigstore-java/pull/965, https://github.com/sigstore/sigstore-java/pull/981

# [1.3.0] - 2025-02-25

## Added
- Add support for verifying dsse sigstore bundles https://github.com/sigstore/sigstore-java/pull/855

# [1.2.0] - 2024-12-4

## Added
- Add option to sigstore conformance cli to verify artifact digests in addition to file paths https://github.com/sigstore/sigstore-java/pull/859

## Security
- Ensure checkpoints for log inclusion proofs in sigstore bundles are correctly
  verified. https://github.com/sigstore/sigstore-java/commit/23fb4885e6704a5df4977f7acf253a745349edf9

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
