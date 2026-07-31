# GitHub private-repo attestation (no transparency log)

`attestation.sigstore.json` and `trusted_root.jsonl` are a real SLSA build-provenance
attestation produced by GitHub Actions for a **private** repository.

Attestations for private repositories are signed by GitHub's own Sigstore instance,
which — unlike the public-good instance — does **not** publish to a transparency log and
does **not** use certificate transparency:

- the bundle carries **zero** transparency-log entries and relies on a signed RFC 3161
  timestamp for trusted time;
- the trust root GitHub distributes for it contains **zero** CT logs.

Verifying such a bundle therefore requires a policy that disables both transparency-log
and certificate-transparency checks (`VerificationOptions` with `TLogOptions` /
`CTLogOptions` `isEnabled(false)`). See `KeylessVerifierTest`.

## Files

- `attestation.sigstore.json` — the Sigstore bundle (DSSE envelope, in-toto SLSA
  provenance predicate).
- `trusted_root.jsonl` — trust roots as JSON Lines. `gh attestation trusted-root` emits
  more than one (public-good first, then GitHub). sigstore-java consumes a single trust
  root, so the test selects the GitHub one (the line describing the `fulcio.githubapp.com`
  CA).

## How this fixture was obtained

Both files are the unmodified output of the `gh` CLI, run against a **private**
repository whose build had already produced a SLSA build-provenance attestation for a
released artifact.

Download the attestation bundle for the built artifact, scoping the lookup to its private
repository:

```sh
gh attestation download <artifact-file> --repo <owner>/<private-repo>
```

This writes a `sha256-<digest>.jsonl` file in the current directory containing the
Sigstore bundle; it is copied verbatim to `attestation.sigstore.json`.

Fetch the matching trust roots (public-good instance first, then GitHub's instance):

```sh
gh attestation trusted-root > trusted_root.jsonl
```

Any private repository with a build-provenance attestation reproduces an equivalent
fixture: because the repository is private, GitHub signs it with its own Sigstore
instance, so the resulting bundle carries no transparency-log entries.
