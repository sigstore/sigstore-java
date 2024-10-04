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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.encoders.DecoderException;
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

  private static final Logger log = Logger.getLogger(Updater.class.getName());

  private final Clock clock;
  private final Verifiers.Supplier verifiers;
  private final MetaFetcher fetcher;
  private final RootProvider trustedRootPath;
  private final MutableTufStore localStore;

  private ZonedDateTime updateStartTime;

  Updater(
      Clock clock,
      Verifiers.Supplier verifiers,
      MetaFetcher fetcher,
      RootProvider trustedRootPath,
      MutableTufStore localStore) {
    this.clock = clock;
    this.verifiers = verifiers;
    this.trustedRootPath = trustedRootPath;
    this.localStore = localStore;
    this.fetcher = fetcher;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Update top level metadata, does not dive into delegations or download targets. */
  public void update()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    // https://theupdateframework.github.io/specification/latest/#detailed-client-workflow}
    var root = updateRoot();
    // only returns a timestamp value if a more recent timestamp file has been found.
    var timestampMaybe = updateTimestamp(root);
    if (timestampMaybe.isPresent()) {
      var snapshot = updateSnapshot(root, timestampMaybe.get());
      updateTargets(root, snapshot);
    }
  }

  /** Update metadata and download targets, if targets is emtpy, this is a no-op */
  public void downloadTargets(String... targetNames)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    if (targetNames.length == 0) {
      return;
    }
    update();
    Optional<Targets> targets = localStore.loadTargets();
    if (targets.isEmpty()) {
      throw new TargetMetadataMissingException();
    }
    for (var targetName : targetNames) {
      downloadTarget(targets.get(), targetName);
    }
  }

  Root updateRoot()
      throws IOException, RoleExpiredException, NoSuchAlgorithmException, InvalidKeySpecException,
          FileExceedsMaxLengthException, RollbackVersionException, SignatureVerificationException {
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
      trustedRoot = GSON.get().fromJson(trustedRootPath.get(), Root.class);
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

  void verifyDelegate(Root trustedRoot, SignedTufMeta<? extends TufMeta> delegate)
      throws SignatureVerificationException, IOException, NoSuchAlgorithmException,
          InvalidKeySpecException {
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
      throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
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
          try {
            // while we error on keys that are not readable, we are intentionally more permissive
            // about signatures. If for ANY reason (except unparsed keys) we cannot validate a
            // signature, we continue as long as we find enough valid signatures within the
            // threshold. We still warn the user as this could be an indicator of data issues
            byte[] signatureBytes = Hex.decode(signature.getSignature());
            if (verifiers.newVerifier(pubKey).verify(verificationMaterial, signatureBytes)) {
              goodSigs.add(signature.getKeyId());
            }
          } catch (SignatureException e) {
            log.log(
                Level.FINE,
                () ->
                    String.format(
                        Locale.ROOT,
                        "TUF: ignored unverifiable signature: '%s' for keyid: '%s'",
                        signature.getSignature(),
                        signature.getKeyId()));
          } catch (DecoderException | NoSuchAlgorithmException | InvalidKeyException e) {
            log.log(
                Level.WARNING,
                e,
                () ->
                    String.format(
                        Locale.ROOT,
                        "TUF: ignored invalid signature: '%s' for keyid: '%s', because '%s'",
                        signature.getSignature(),
                        keyid,
                        e.getMessage()));
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
    int timestampSnapshotVersion = timestamp.getSignedMeta().getSnapshotMeta().getVersion();
    var snapshotResult =
        fetcher.getMeta(
            Role.Name.SNAPSHOT,
            timestampSnapshotVersion,
            Snapshot.class,
            timestamp.getSignedMeta().getSnapshotMeta().getLengthOrDefault());
    if (snapshotResult.isEmpty()) {
      throw new FileNotFoundException(
          timestampSnapshotVersion + ".snapshot.json", fetcher.getSource());
    }
    // 2) check against timestamp.snapshot.hash, this is optional, the fallback is
    // that the version must match, which is handled in (4).
    var snapshot = snapshotResult.get();
    if (timestamp.getSignedMeta().getSnapshotMeta().getHashes().isPresent()) {
      verifyHashes(
          "snapshot",
          snapshot.getRawBytes(),
          timestamp.getSignedMeta().getSnapshotMeta().getHashes().get());
    }
    // 3) Check against threshold of root signing keys, else fail
    verifyDelegate(root, snapshot.getMetaResource());
    // 4) Check snapshot.version matches timestamp.snapshot.version, else fail.
    int snapshotVersion = snapshot.getMetaResource().getSignedMeta().getVersion();
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
    SnapshotMeta.SnapshotTarget targetMeta = snapshot.getSignedMeta().getTargetMeta("targets.json");
    var targetsResultMaybe =
        fetcher.getMeta(
            Role.Name.TARGETS,
            targetMeta.getVersion(),
            Targets.class,
            targetMeta.getLengthOrDefault());
    if (targetsResultMaybe.isEmpty()) {
      throw new FileNotFoundException(
          targetMeta.getVersion() + ".targets.json", fetcher.getSource());
    }
    var targetsResult = targetsResultMaybe.get();
    // 2) check hash against snapshot.targets.hash, else just make sure versions match, handled
    // by (4)
    if (targetMeta.getHashes().isPresent()) {
      verifyHashes(
          targetMeta.getVersion() + ".targets.json",
          targetsResult.getRawBytes(),
          targetMeta.getHashes().get());
    }
    // 3) check against threshold of keys as specified by trusted root.json
    verifyDelegate(root, targetsResult.getMetaResource());
    // 4) check targets.version == snapshot.targets.version, else fail.
    int targetsVersion = targetsResult.getMetaResource().getSignedMeta().getVersion();
    int snapshotTargetsVersion = targetMeta.getVersion();
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

  void downloadTarget(Targets targets, String targetName)
      throws IOException, TargetMetadataMissingException, FileNotFoundException {
    // TODO: 7) delegations are not supported by this client yet
    TargetMeta.TargetData targetData = targets.getSignedMeta().getTargets().get(targetName);
    // 8) If target is missing metadata fail.
    if (targetData == null) {
      throw new TargetMetadataMissingException(targetName);
    }
    // 9) Download target up to length specified in bytes. verify against hash.
    String versionedTargetName;
    if (targetData.getHashes().getSha512() != null) {
      versionedTargetName = targetData.getHashes().getSha512() + "." + targetName;
    } else {
      versionedTargetName = targetData.getHashes().getSha256() + "." + targetName;
    }

    // TODO: use local cache if available
    var targetBytes =
        fetcher.fetchResource("targets/" + versionedTargetName, targetData.getLength());
    if (targetBytes == null) {
      throw new FileNotFoundException(targetName, fetcher.getSource());
    }
    verifyHashes(targetName, targetBytes, targetData.getHashes());

    // when persisting targets use the targetname without sha512 prefix
    // https://theupdateframework.github.io/specification/latest/index.html#fetch-target
    localStore.storeTargetFile(targetName, targetBytes);
  }

  @VisibleForTesting
  MutableTufStore getLocalStore() {
    return localStore;
  }

  public static class Builder {
    private Clock clock = Clock.systemUTC();
    private Verifiers.Supplier verifiers = Verifiers::newVerifier;

    private MetaFetcher fetcher;
    private RootProvider trustedRootPath;
    private MutableTufStore localStore;

    public Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder setVerifiers(Verifiers.Supplier verifiers) {
      this.verifiers = verifiers;
      return this;
    }

    public Builder setLocalStore(MutableTufStore store) {
      this.localStore = store;
      return this;
    }

    public Builder setTrustedRootPath(RootProvider trustedRootPath) {
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
