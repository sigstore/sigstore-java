/*
 * Copyright 2022 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.sigstore.tuf;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.hash.Hashing;
import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.tuf.model.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tuf metadata updater. Implements updating your trusted metadata from a single TUF mirror.
 *
 * @see <a
 *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">TUF
 *     client workflow</a>
 */
public class Updater {

  // Limit the update loop to retrieve a max of 1024 subsequent versions as expressed in 5.3.3 of
  // spec.
  private static final int MAX_UPDATES = 1024;

  private Clock clock;
  private Verifiers.Supplier verifiers;
  private MetaFetcher fetcher;
  private ZonedDateTime updateStartTime;
  private Path trustedRootPath;
  private TufLocalStore localStore;

  Updater(
      Clock clock,
      Verifiers.Supplier verifiers,
      MetaFetcher fetcher,
      Path trustedRootPath,
      TufLocalStore localStore) {
    this.clock = clock;
    this.verifiers = verifiers;
    this.trustedRootPath = trustedRootPath;
    this.localStore = localStore;
    this.fetcher = fetcher;
  }

  public static Builder builder() {
    return new Builder();
  }

  public void update()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    var root = updateRoot();
    // only returns a timestamp value if a more recent timestamp file has been found.
    var timestampMaybe = updateTimestamp(root);
    if (timestampMaybe.isPresent()) {
      var snapshot = updateSnapshot(root, timestampMaybe.get());
      updateTargets(root, snapshot);
    }
  }

  // https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
  Root updateRoot()
      throws IOException, RoleExpiredException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidKeyException, FileExceedsMaxLengthException, RollbackVersionException,
          SignatureVerificationException {
    // 5.3.1) record the time at start and use for expiration checks consistently throughout the
    // update.
    updateStartTime = ZonedDateTime.now(clock);

    // 5.3.2) load the trust metadata file (root.json), get version of root.json and the role
    // signature threshold value
    Optional<Root> localRoot = localStore.loadTrustedRoot();
    Root trustedRoot;
    if (localRoot.isPresent()) {
      trustedRoot = localRoot.get();
    } else {
      trustedRoot = GSON.get().fromJson(Files.readString(trustedRootPath), Root.class);
    }
    int baseVersion = trustedRoot.getSignedMeta().getVersion();
    int nextVersion = baseVersion + 1;
    // keep these for verifying the last step. 5.3.11
    var preUpdateSnapshotRole = trustedRoot.getSignedMeta().getRoles().get("snapshot");
    var preUpdateTimestampRole = trustedRoot.getSignedMeta().getRoles().get("timestamp");

    while (nextVersion < baseVersion + MAX_UPDATES) {
      // 5.3.3) download $version+1.root.json from mirror url (eventually obtained from remote.json
      // or map.json) up MAX_META_BYTES. If the file is not available, or we have reached
      // MAX_UPDATES number of root metadata files go to step 5.3.10
      var newRootMaybe = fetcher.getRootAtVersion(nextVersion);
      if (newRootMaybe.isEmpty()) {
        // No newer versions, go to 5.3.10.
        break;
      }
      var newRoot = newRootMaybe.get().getMetaResource();
      // 5.3.4) we have a valid next version of the root.json. Check that the file has been signed
      // by:
      //   a) a threshold (from step 2) of keys specified in the trusted metadata
      //   b) and a threshold of keys in the new root.json.
      //    Fail if either a or b aren't true.

      verifyDelegate(trustedRoot, newRoot);
      verifyDelegate(newRoot, newRoot);

      // 5.3.5) We've taken the liberty to modify 5.3.5 to just validate that the new root meta
      // matches the version we pulled based off of the pattern {version}.root.json. We know due to
      // the loop constraints that it is larger than the current version.
      if (newRoot.getSignedMeta().getVersion() != nextVersion) {
        throw new RollbackVersionException(nextVersion, newRoot.getSignedMeta().getVersion());
      }
      // 5.3.7) set the trusted root metadata to the new root
      trustedRoot = newRoot;
      // 5.3.8) persist to repo
      localStore.storeTrustedRoot(trustedRoot);
      // 5.3.9) see if there are more versions go back 5.3.3
      nextVersion++;
    }

    // 5.3.10) Check expiration timestamp in trusted root is higher than fixed update start time,
    // otherwise throw error.
    ZonedDateTime expires = trustedRoot.getSignedMeta().getExpiresAsDate();
    throwIfExpired(expires);
    // 5.3.11) If the timestamp and / or snapshot keys have been rotated, then delete the trusted
    // timestamp and snapshot metadata files.
    if (hasNewKeys(preUpdateSnapshotRole, trustedRoot.getSignedMeta().getRole(Role.Name.SNAPSHOT))
        || hasNewKeys(
            preUpdateTimestampRole, trustedRoot.getSignedMeta().getRole(Role.Name.TIMESTAMP))) {
      localStore.clearMetaDueToKeyRotation();
    }
    return trustedRoot;
  }

  private void throwIfExpired(ZonedDateTime expires) {
    if (expires.isBefore(updateStartTime)) {
      throw new RoleExpiredException(fetcher.getSource(), updateStartTime, expires);
    }
  }

  private boolean hasNewKeys(RootRole oldRole, RootRole newRole) {
    return !newRole.getKeyids().stream().allMatch(key -> oldRole.getKeyids().contains(key));
  }

  void verifyDelegate(Root trustedRoot, SignedTufMeta delegate)
      throws SignatureVerificationException, IOException, NoSuchAlgorithmException,
          InvalidKeySpecException, InvalidKeyException {
    verifyDelegate(
        delegate.getSignatures(),
        trustedRoot.getSignedMeta().getKeys(),
        trustedRoot
            .getSignedMeta()
            .getRole(
                Role.Name.valueOf(delegate.getSignedMeta().getType().toUpperCase(Locale.ROOT))),
        delegate.getCanonicalSignedBytes());
  }

  /**
   * Verifies that a delegate role has been signed by the threshold amount of keys.
   *
   * @param signatures these are the signatures on the role meta we're verifying
   * @param publicKeys a map of key IDs to public keys used for signing various roles
   * @param role the key ids and threshold values for role signing
   * @param verificationMaterial the contents to be verified for authenticity
   * @throws SignatureVerificationException if there are not enough verified signatures
   */
  @VisibleForTesting
  void verifyDelegate(
      List<Signature> signatures,
      Map<String, Key> publicKeys,
      Role role,
      byte[] verificationMaterial)
      throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException,
          InvalidKeySpecException, IOException {
    // use set to not count the same key multiple times towards the threshold.
    var goodSigs = new HashSet<>(role.getKeyids().size() * 4 / 3);
    // role.getKeyIds() defines the keys allowed to sign for this role.
    for (String keyid : role.getKeyids()) {
      Optional<Signature> signatureMaybe =
          signatures.stream().filter(sig -> sig.getKeyId().equals(keyid)).findFirst();
      // only verify if we find a signature that matches an allowed key id.
      if (signatureMaybe.isPresent()) {
        var signature = signatureMaybe.get();
        // look for the public key that matches the key ID and use it for verification.
        var key = publicKeys.get(signature.getKeyId());
        if (key != null) {
          String publicKeyContents = key.getKeyVal().get("public");
          PublicKey pubKey;
          // TUF root version 4 and less is raw hex encoded key while 5+ is PEM.
          // TODO(patrick@chainguard.dev): remove hex handling code once we upgrade the trusted root
          // to v5.
          if (publicKeyContents.startsWith("-----BEGIN PUBLIC KEY-----")) {
            pubKey = Keys.parsePublicKey(publicKeyContents.getBytes(StandardCharsets.UTF_8));
          } else {
            pubKey = Keys.constructTufPublicKey(Hex.decode(publicKeyContents), key.getScheme());
          }
          byte[] signatureBytes = Hex.decode(signature.getSignature());
          try {
            if (verifiers.newVerifier(pubKey).verify(verificationMaterial, signatureBytes)) {
              goodSigs.add(signature.getKeyId());
            }
          } catch (SignatureException e) {
            throw new TufException(e);
          }
        }
      }
    }
    if (goodSigs.size() < role.getThreshold()) {
      throw new SignatureVerificationException(role.getThreshold(), goodSigs.size());
    }
  }

  Optional<Timestamp> updateTimestamp(Root root)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          FileNotFoundException, SignatureVerificationException {
    // 1) download the timestamp.json bytes.
    var timestamp =
        fetcher
            .getMeta(Role.Name.TIMESTAMP, Timestamp.class)
            .orElseThrow(() -> new FileNotFoundException("timestamp.json", fetcher.getSource()))
            .getMetaResource();

    // 2) verify against threshold of keys as specified in trusted root.json
    verifyDelegate(root, timestamp);

    // 3) If the new timestamp file has a lesser version than our current trusted timestamp file
    // report a rollback attack.  If it is equal abort the update as there should be no changes. If
    // it is higher than continue update.
    Optional<Timestamp> localTimestampMaybe = localStore.loadTimestamp();
    if (localTimestampMaybe.isPresent()) {
      Timestamp localTimestamp = localTimestampMaybe.get();
      if (localTimestamp.getSignedMeta().getVersion() > timestamp.getSignedMeta().getVersion()) {
        throw new RollbackVersionException(
            localTimestamp.getSignedMeta().getVersion(), timestamp.getSignedMeta().getVersion());
      }
      if (localTimestamp.getSignedMeta().getVersion() == timestamp.getSignedMeta().getVersion()) {
        return Optional.empty();
      }
    }
    // 4) check expiration timestamp is after tuf update start time, else fail.
    throwIfExpired(timestamp.getSignedMeta().getExpiresAsDate());
    // 5) persist timestamp.json
    localStore.storeMeta(timestamp);
    return Optional.of(timestamp);
  }

  Snapshot updateSnapshot(Root root, Timestamp timestamp)
      throws IOException, FileNotFoundException, InvalidHashesException,
          SignatureVerificationException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidKeyException {
    // 1) download the snapshot.json bytes up to timestamp's snapshot length.
    // TODO(patrick@chainguard.dev): Looks like sigstore TUF moved to using
    // consistent snapshots for this meta file.
    // Update to pull from
    //    "{timestamp.getSignedMeta().getSnapshotMeta().getVersion()}.snapshot.json".
    // Presumably we should also write that file to disk as well as update the
    //     'snapshot.json'
    var snapshotResult =
        fetcher.getMeta(
            Role.Name.SNAPSHOT,
            Snapshot.class,
            timestamp.getSignedMeta().getSnapshotMeta().getLength());
    if (snapshotResult.isEmpty()) {
      throw new FileNotFoundException("snapshot.json", fetcher.getSource());
    }
    // 2) check against timestamp.snapshot.hash
    var snapshot = snapshotResult.get();
    verifyHashes(
        "snapshot",
        snapshot.getRawBytes(),
        timestamp.getSignedMeta().getSnapshotMeta().getHashes());
    // 3) Check against threshold of root signing keys, else fail
    verifyDelegate(root, snapshot.getMetaResource());
    // 4) Check snapshot.version matches timestamp.snapshot.version, else fail.
    int snapshotVersion = snapshot.getMetaResource().getSignedMeta().getVersion();
    int timestampSnapshotVersion = timestamp.getSignedMeta().getSnapshotMeta().getVersion();
    if (snapshotVersion != timestampSnapshotVersion) {
      throw new SnapshotVersionMismatchException(timestampSnapshotVersion, snapshotVersion);
    }
    // 5) Ensure all targets and delegated targets in the trusted (old) snapshots file have versions
    // which are less than or equal to the equivalent target in the new file.  Check that no targets
    // are missing in new file. Else fail.
    var trustedSnapshotMaybe = localStore.loadSnapshot();
    if (trustedSnapshotMaybe.isPresent()) {
      var trustedSnapshot = trustedSnapshotMaybe.get();
      for (Map.Entry<String, SnapshotMeta.SnapshotTarget> trustedTargetEntry :
          trustedSnapshot.getSignedMeta().getMeta().entrySet()) {
        var newTargetMeta =
            snapshot.getMetaResource().getSignedMeta().getMeta().get(trustedTargetEntry.getKey());
        if (newTargetMeta == null) {
          throw new SnapshotTargetMissingException(trustedTargetEntry.getKey());
        }
        if (newTargetMeta.getVersion() < trustedTargetEntry.getValue().getVersion()) {
          throw new SnapshotTargetVersionException(
              trustedTargetEntry.getKey(),
              newTargetMeta.getVersion(),
              trustedTargetEntry.getValue().getVersion());
        }
      }
    }

    // 6) Ensure expiration timestamp of snapshot is later than tuf update start time.
    throwIfExpired(snapshot.getMetaResource().getSignedMeta().getExpiresAsDate());
    // 7) persist snapshot.
    localStore.storeMeta(snapshot.getMetaResource());
    return snapshot.getMetaResource();
  }

  // this method feels very wrong. I would not show it to a friend.
  @VisibleForTesting
  static void verifyHashes(String name, byte[] data, Hashes hashes) throws InvalidHashesException {
    List<InvalidHashesException.InvalidHash> badHashes = new ArrayList<>(2);
    String expectedSha512 = hashes.getSha512();
    String expectedSha256 = hashes.getSha256();
    if (expectedSha256 == null && expectedSha512 == null) {
      throw new IllegalArgumentException(
          String.format(
              Locale.ROOT,
              "hashes parameter for %s must contain at least one of sha512 or sha256.",
              name));
    }
    String computedSha512 = Hashing.sha512().hashBytes(data).toString();
    if (expectedSha512 != null && !computedSha512.equals(expectedSha512)) {
      badHashes.add(
          new InvalidHashesException.InvalidHash("sha512", expectedSha512, computedSha512));
    }
    String computedSha256 = Hashing.sha256().hashBytes(data).toString();
    if (expectedSha256 != null && !computedSha256.equals(expectedSha256)) {
      badHashes.add(
          new InvalidHashesException.InvalidHash("sha256", expectedSha256, computedSha256));
    }
    if (!badHashes.isEmpty()) {
      throw new InvalidHashesException(
          name, badHashes.toArray(InvalidHashesException.InvalidHash[]::new));
    }
  }

  Targets updateTargets(Root root, Snapshot snapshot)
      throws IOException, FileNotFoundException, InvalidHashesException,
          SignatureVerificationException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidKeyException, FileExceedsMaxLengthException {
    // 1) download the targets.json up to targets.json length in bytes.
    var targetsResultMaybe =
        fetcher.getMeta(
            Role.Name.TARGETS,
            Targets.class,
            snapshot.getSignedMeta().getTargetMeta("targets.json").getLength());
    if (targetsResultMaybe.isEmpty()) {
      throw new FileNotFoundException("targets.json", fetcher.getSource());
    }
    var targetsResult = targetsResultMaybe.get();
    // 2) check hash against snapshot.targets.hash, else fail.
    verifyHashes(
        "targets.json",
        targetsResult.getRawBytes(),
        snapshot.getSignedMeta().getTargetMeta("targets.json").getHashes());
    // 3) check against threshold of keys as specified by trusted root.json
    verifyDelegate(root, targetsResult.getMetaResource());
    // 4) check targets.version == snapshot.targets.version, else fail.
    int targetsVersion = targetsResult.getMetaResource().getSignedMeta().getVersion();
    int snapshotTargetsVersion =
        snapshot.getSignedMeta().getTargetMeta("targets.json").getVersion();
    if (targetsVersion != snapshotTargetsVersion) {
      throw new SnapshotVersionMismatchException(snapshotTargetsVersion, targetsVersion);
    }
    // 5) check expiration is after tuf update start time
    throwIfExpired(targetsResult.getMetaResource().getSignedMeta().getExpiresAsDate());
    // 6) persist targets metadata
    // why do we persist the
    localStore.storeMeta(targetsResult.getMetaResource());
    return targetsResult.getMetaResource();
  }

  void downloadTargets(Targets targets)
      throws IOException, TargetMetadataMissingException, FileNotFoundException {
    // Skip #7 and go straight to downloading targets. It looks like delegations were removed from
    // sigstore TUF data.
    // {@see https://github.com/sigstore/sigstore/issues/562}
    for (Map.Entry<String, TargetMeta.TargetData> entry :
        targets.getSignedMeta().getTargets().entrySet()) {
      String targetName = entry.getKey();
      // 8) If target is missing metadata fail.
      // Note: This can't actually happen due to the way GSON is setup the targets.json would fail
      // to parse. Leaving
      // this code in in-case we eventually allow it in de-serialization.
      if (entry.getValue() == null) {
        throw new TargetMetadataMissingException(targetName);
      }
      TargetMeta.TargetData targetData = entry.getValue();
      // 9) Download target up to length specified in bytes. verify against hash.
      // TODO(patrick@chainguard.dev): Update this code to use consistent snapshots.
      // e.g. "{targetData.getHashes().getSha512()}.{targetName}"
      var targetBytes = fetcher.fetchResource("targets/" + targetName, targetData.getLength());
      if (targetBytes == null) {
        throw new FileNotFoundException(targetName, fetcher.getSource());
      }
      verifyHashes(entry.getKey(), targetBytes, targetData.getHashes());
      localStore.storeTargetFile(targetName, targetBytes);
    }
  }

  @VisibleForTesting
  TufLocalStore getLocalStore() {
    return localStore;
  }

  public static class Builder {
    private Clock clock = Clock.systemUTC();
    private Verifiers.Supplier verifiers = Verifiers::newVerifier;

    private MetaFetcher fetcher;
    private Path trustedRootPath;
    private TufLocalStore localStore;

    public Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder setVerifiers(Verifiers.Supplier verifiers) {
      this.verifiers = verifiers;
      return this;
    }

    public Builder setLocalStore(TufLocalStore store) {
      this.localStore = store;
      return this;
    }

    public Builder setTrustedRootPath(Path trustedRootPath) {
      this.trustedRootPath = trustedRootPath;
      return this;
    }

    public Builder setFetcher(MetaFetcher fetcher) {
      this.fetcher = fetcher;
      return this;
    }

    public Updater build() {
      return new Updater(clock, verifiers, fetcher, trustedRootPath, localStore);
    }
  }
}
