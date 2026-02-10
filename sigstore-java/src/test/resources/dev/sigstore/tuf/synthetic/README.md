# Synthetic TUF Test Repos

This directory contains synthetic TUF repositories used by `UpdaterTest` and `DelegationTest`.

## Generating updater tests

These were previously generated using a very old version of go-tuf.

## Generating delegation repos

The `delegation-basic/`, `delegation-terminating/`, and `delegation-non-terminating/` repos
(plus `delegation-trusted-root.json`) were generated using python-tuf. To regenerate them,
save the script below as `generate_delegation_repos.py` in this directory and run it:

```bash
~/src/tuf-conformance/env/bin/python3 generate_delegation_repos.py
```

This requires `python-tuf` and `securesystemslib[crypto]` to be installed. The
tuf-conformance virtualenv already has these dependencies.

After regenerating, update the target file hashes in `DelegationTest.java` to match
the new sha256 values (the hashes change because the keys are regenerated).

### Repos produced

- **delegation-basic/** - Top-level targets delegates `release/*` to a `release` role which
  contains `release/artifact.txt`. Tests basic delegation resolution.
- **delegation-terminating/** - Delegates to `release` (terminating, paths `release/*`) then
  `fallback` (paths `*`). The `release` role is empty, so searching for `release/missing.txt`
  stops at the terminating role without reaching `fallback`.
- **delegation-non-terminating/** - Delegates to `staging` (non-terminating, paths `*`) then
  `production` (paths `*`). `staging` is empty, so search continues past it to `production`
  where `found.txt` is found.
- **delegation-trusted-root.json** - Shared bootstrap root used by all three repos.

### Script

```python
#!/usr/bin/env python3
"""Generate synthetic TUF repos with delegations for DelegationTest.java.

Usage (from tuf-conformance venv):
  ~/src/tuf-conformance/env/bin/python3 generate_delegation_repos.py

Generates 3 repos under the current directory:
  delegation-basic/           - simple delegation with target found in child role
  delegation-terminating/     - terminating delegation stops search
  delegation-non-terminating/ - non-terminating delegation allows search to continue

Also generates delegation-trusted-root.json (the bootstrap root).
"""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

EXPIRY = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
SPEC_VERSION = "1.0"
SCRIPT_DIR = Path(__file__).parent


def generate_keys():
    """Generate signing keys for all top-level roles."""
    return {
        "root": CryptoSigner.generate_ecdsa(),
        "targets": CryptoSigner.generate_ecdsa(),
        "snapshot": CryptoSigner.generate_ecdsa(),
        "timestamp": CryptoSigner.generate_ecdsa(),
    }


def create_root(signers):
    """Create and sign root metadata."""
    root = Root(spec_version=SPEC_VERSION, expires=EXPIRY, consistent_snapshot=True)
    for role_name, signer in signers.items():
        root.add_key(signer.public_key, role_name)
    root_md = Metadata(root)
    root_md.sign(signers["root"])
    return root_md


def create_targets_with_delegations(signers, delegation_signers, delegation_roles):
    """Create top-level targets with delegation configuration."""
    keys = {}
    for role_name, signer in delegation_signers.items():
        key = signer.public_key
        keys[key.keyid] = key

    delegations = Delegations(keys=keys, roles=delegation_roles)
    targets = Targets(
        spec_version=SPEC_VERSION, expires=EXPIRY, delegations=delegations
    )
    targets_md = Metadata(targets)
    targets_md.sign(signers["targets"])
    return targets_md


def create_delegated_targets(delegation_signer, target_files=None):
    """Create delegated targets metadata, optionally with target files."""
    targets = Targets(spec_version=SPEC_VERSION, expires=EXPIRY)
    if target_files:
        for name, content in target_files.items():
            targets.targets[name] = TargetFile.from_data(name, content)
    targets_md = Metadata(targets)
    targets_md.sign(delegation_signer)
    return targets_md


def create_snapshot(signers, targets_version, delegated_roles_meta=None):
    """Create snapshot metadata referencing targets and delegated roles."""
    snapshot = Snapshot(spec_version=SPEC_VERSION, expires=EXPIRY)
    snapshot.meta["targets.json"].version = targets_version

    if delegated_roles_meta:
        for role_name, (version, md_bytes) in delegated_roles_meta.items():
            snapshot.meta[f"{role_name}.json"] = MetaFile(version=version)

    snapshot_md = Metadata(snapshot)
    snapshot_md.sign(signers["snapshot"])
    return snapshot_md


def create_timestamp(signers, snapshot_version):
    """Create timestamp metadata."""
    timestamp = Timestamp(spec_version=SPEC_VERSION, expires=EXPIRY)
    timestamp.snapshot_meta.version = snapshot_version
    timestamp_md = Metadata(timestamp)
    timestamp_md.sign(signers["timestamp"])
    return timestamp_md


def serialize(md):
    """Serialize metadata to bytes."""
    serializer = JSONSerializer()
    return md.to_bytes(serializer)


def write_target_file(repo_dir, target_name, content):
    """Write a target file with hash-prefixed filename to targets/ dir.

    Uses sha256 prefix to match TargetFile.from_data() which only generates sha256.
    The Updater falls back to sha256 when sha512 is not in the metadata.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    targets_dir = repo_dir / "targets"
    # Handle subdirectories in target names
    target_subdir = targets_dir / Path(target_name).parent
    target_subdir.mkdir(parents=True, exist_ok=True)
    filename = Path(target_name).name
    target_path = target_subdir / f"{sha256}.{filename}"
    target_path.write_bytes(content)


def write_repo(repo_dir, root_md, targets_md, snapshot_md, timestamp_md,
               delegated_mds=None, target_contents=None):
    """Write all metadata files to the repo directory."""
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    root_bytes = serialize(root_md)
    targets_bytes = serialize(targets_md)
    snapshot_bytes = serialize(snapshot_md)
    timestamp_bytes = serialize(timestamp_md)

    root_version = root_md.signed.version
    targets_version = targets_md.signed.version
    snapshot_version = snapshot_md.signed.version

    # Root: versioned + unversioned
    (repo_dir / f"{root_version}.root.json").write_bytes(root_bytes)
    (repo_dir / "root.json").write_bytes(root_bytes)

    # Targets: versioned
    (repo_dir / f"{targets_version}.targets.json").write_bytes(targets_bytes)

    # Snapshot: versioned
    (repo_dir / f"{snapshot_version}.snapshot.json").write_bytes(snapshot_bytes)

    # Timestamp: unversioned
    (repo_dir / "timestamp.json").write_bytes(timestamp_bytes)

    # Delegated targets: versioned
    if delegated_mds:
        for role_name, md in delegated_mds.items():
            version = md.signed.version
            md_bytes = serialize(md)
            (repo_dir / f"{version}.{role_name}.json").write_bytes(md_bytes)

    # Target files
    if target_contents:
        for name, content in target_contents.items():
            write_target_file(repo_dir, name, content)

    return root_bytes


def generate_delegation_basic(signers):
    """Repo 1: delegation-basic
    Top-level targets delegates 'release/*' to 'release' role.
    'release' role contains target 'release/artifact.txt'.
    """
    release_signer = CryptoSigner.generate_ecdsa()

    delegation_role = DelegatedRole(
        name="release",
        keyids=[release_signer.public_key.keyid],
        threshold=1,
        terminating=False,
        paths=["release/*"],
    )

    targets_md = create_targets_with_delegations(
        signers, {"release": release_signer}, {delegation_role.name: delegation_role}
    )

    target_content = b"artifact content"
    release_md = create_delegated_targets(
        release_signer, {"release/artifact.txt": target_content}
    )

    delegated_roles_meta = {"release": (release_md.signed.version, serialize(release_md))}
    snapshot_md = create_snapshot(signers, targets_md.signed.version, delegated_roles_meta)
    timestamp_md = create_timestamp(signers, snapshot_md.signed.version)

    repo_dir = SCRIPT_DIR / "delegation-basic"
    root_bytes = write_repo(
        repo_dir, create_root(signers), targets_md, snapshot_md, timestamp_md,
        {"release": release_md},
        {"release/artifact.txt": target_content},
    )
    return repo_dir


def generate_delegation_terminating(signers):
    """Repo 2: delegation-terminating
    Top-level targets delegates to 'release' (terminating=true, paths=['release/*'])
    then 'fallback' (paths=['*']).
    'release' exists but does NOT contain 'release/missing.txt'.
    Because 'release' is terminating and matches the path, search stops
    without checking 'fallback'.
    """
    release_signer = CryptoSigner.generate_ecdsa()
    fallback_signer = CryptoSigner.generate_ecdsa()

    release_role = DelegatedRole(
        name="release",
        keyids=[release_signer.public_key.keyid],
        threshold=1,
        terminating=True,
        paths=["release/*"],
    )
    fallback_role = DelegatedRole(
        name="fallback",
        keyids=[fallback_signer.public_key.keyid],
        threshold=1,
        terminating=False,
        paths=["*"],
    )

    targets_md = create_targets_with_delegations(
        signers,
        {"release": release_signer, "fallback": fallback_signer},
        {release_role.name: release_role, fallback_role.name: fallback_role},
    )

    # release has no targets (empty)
    release_md = create_delegated_targets(release_signer)

    # fallback has the target (but should never be reached)
    fallback_content = b"fallback content"
    fallback_md = create_delegated_targets(
        fallback_signer, {"release/missing.txt": fallback_content}
    )

    delegated_roles_meta = {
        "release": (release_md.signed.version, serialize(release_md)),
        "fallback": (fallback_md.signed.version, serialize(fallback_md)),
    }
    snapshot_md = create_snapshot(signers, targets_md.signed.version, delegated_roles_meta)
    timestamp_md = create_timestamp(signers, snapshot_md.signed.version)

    repo_dir = SCRIPT_DIR / "delegation-terminating"
    write_repo(
        repo_dir, create_root(signers), targets_md, snapshot_md, timestamp_md,
        {"release": release_md, "fallback": fallback_md},
        {"release/missing.txt": fallback_content},
    )
    return repo_dir


def generate_delegation_non_terminating(signers):
    """Repo 3: delegation-non-terminating
    Top-level targets delegates to 'staging' (terminating=false, paths=['*'])
    then 'production' (paths=['*']).
    'staging' exists but doesn't have the target 'found.txt'.
    'production' has 'found.txt'.
    Search continues past non-terminating 'staging' to 'production'.
    """
    staging_signer = CryptoSigner.generate_ecdsa()
    production_signer = CryptoSigner.generate_ecdsa()

    staging_role = DelegatedRole(
        name="staging",
        keyids=[staging_signer.public_key.keyid],
        threshold=1,
        terminating=False,
        paths=["*"],
    )
    production_role = DelegatedRole(
        name="production",
        keyids=[production_signer.public_key.keyid],
        threshold=1,
        terminating=False,
        paths=["*"],
    )

    targets_md = create_targets_with_delegations(
        signers,
        {"staging": staging_signer, "production": production_signer},
        {staging_role.name: staging_role, production_role.name: production_role},
    )

    # staging has no targets
    staging_md = create_delegated_targets(staging_signer)

    # production has the target
    target_content = b"found content"
    production_md = create_delegated_targets(
        production_signer, {"found.txt": target_content}
    )

    delegated_roles_meta = {
        "staging": (staging_md.signed.version, serialize(staging_md)),
        "production": (production_md.signed.version, serialize(production_md)),
    }
    snapshot_md = create_snapshot(signers, targets_md.signed.version, delegated_roles_meta)
    timestamp_md = create_timestamp(signers, snapshot_md.signed.version)

    repo_dir = SCRIPT_DIR / "delegation-non-terminating"
    write_repo(
        repo_dir, create_root(signers), targets_md, snapshot_md, timestamp_md,
        {"staging": staging_md, "production": production_md},
        {"found.txt": target_content},
    )
    return repo_dir


def main():
    # Use shared keys for all repos so they share one trusted root
    signers = generate_keys()
    root_md = create_root(signers)

    # Write shared trusted root
    trusted_root_path = SCRIPT_DIR / "delegation-trusted-root.json"
    trusted_root_path.write_bytes(serialize(root_md))
    print(f"Wrote {trusted_root_path}")

    generate_delegation_basic(signers)
    print("Generated delegation-basic/")

    generate_delegation_terminating(signers)
    print("Generated delegation-terminating/")

    generate_delegation_non_terminating(signers)
    print("Generated delegation-non-terminating/")

    print("Done!")


if __name__ == "__main__":
    main()
```
