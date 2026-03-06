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
import dev.sigstore.json.JsonParseException;
import dev.sigstore.tuf.encryption.Verifiers;
import dev.sigstore.tuf.model.*;
import dev.sigstore.tuf.model.TargetMeta.TargetData;
import dev.sigstore.tuf.model.Targets;
import dev.sigstore.tuf.model.Timestamp;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
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
  private static final int MAX_DELEGATIONS = 32;

  private static final Logger log = Logger.getLogger(Updater.class.getName());

  private final Clock clock;
  private final Verifiers.Supplier verifiers;
  private final MetaFetcher metaFetcher;
  private final Fetcher targetFetcher;
  private final RootProvider trustedRootPath;

  private final TrustedMetaStore trustedMetaStore;
  private final TargetStore targetStore;

  // Mutable State
  private ZonedDateTime updateStartTime;

  Updater(
      Clock clock,
      Verifiers.Supplier verifiers,
      MetaFetcher metaFetcher,
      Fetcher targetFetcher,
      RootProvider trustedRootPath,
      TrustedMetaStore trustedMetaStore,
      TargetStore targetStore) {
    this.clock = clock;
    this.verifiers = verifiers;
    this.trustedRootPath = trustedRootPath;
    this.metaFetcher = metaFetcher;
    this.targetFetcher = targetFetcher;
    this.trustedMetaStore = trustedMetaStore;
    this.targetStore = targetStore;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Refresh metadata (root → timestamp → snapshot → targets) without downloading targets. */
  public void refresh() throws IOException, JsonParseException {
    updateRoot();
    var oldTimestamp = trustedMetaStore.findTimestamp();
    updateTimestamp();
    if (!Objects.equals(oldTimestamp.orElse(null), trustedMetaStore.getTimestamp())
        || trustedMetaStore.findSnapshot().isEmpty()
        || trustedMetaStore.findTargets().isEmpty()) {
      // if we need to update or we can't find targets/snapshots locally then grab new snapshot and
      // targets from remote
      updateSnapshot();
      updateTargets();
    }
  }

  /**
   * Download a single target defined in targets. Will not re-download a target that is already
   * cached locally. Supports delegated targets.
   */
  public void downloadTarget(String targetName) throws IOException, JsonParseException {
    var targetDataMaybe = findTargetData(targetName, trustedMetaStore.getTargets());
    if (targetDataMaybe.isEmpty()) {
      throw new TargetMetadataMissingException(targetName);
    }
    TargetData targetData = targetDataMaybe.get();
    if (targetStore.hasTarget(targetName)) {
      byte[] target = targetStore.readTarget(targetName);
      // TODO: Using exceptions for control flow here, we should have something that returns a true
      // TODO: or false on hashes, but requires reworking verifyHashes.
      try {
        verifyHashes(targetName, target, targetData.getHashes());
        // found a valid cached instance of the target
        return;
      } catch (InvalidHashesException ioe) {
        // continue to download targets
      }
    }
    downloadTarget(targetName, targetData);
  }

  // https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
  void updateRoot()
      throws IOException,
          RoleExpiredException,
          FileExceedsMaxLengthException,
          RollbackVersionException,
          SignatureVerificationException,
          JsonParseException {
    // 5.3.1) record the time at start and use for expiration checks consistently throughout the
    // update.
    updateStartTime = ZonedDateTime.now(clock);

    // 5.3.2) load the trust metadata file (root.json), get version of root.json and the role
    // signature threshold value
    Optional<Root> localRoot = trustedMetaStore.findRoot();
    Root trustedRoot;
    if (localRoot.isPresent()) {
      trustedRoot = localRoot.get();
    } else {
      trustedRoot = GSON.get().fromJson(trustedRootPath.get(), Root.class);
      trustedMetaStore.setRoot(trustedRoot);
    }
    // verify root that we're bootstrapping this update with is good to go
    verifyDelegate(trustedRoot, trustedRoot);

    int baseVersion = trustedRoot.getSignedMeta().getVersion();
    int nextVersion = baseVersion + 1;
    // keep these for verifying the last step. 5.3.11
    var preUpdateSnapshotRole = trustedRoot.getSignedMeta().getRoles().get("snapshot");
    var preUpdateTimestampRole = trustedRoot.getSignedMeta().getRoles().get("timestamp");

    while (nextVersion < baseVersion + MAX_UPDATES) {
      // 5.3.3) download $version+1.root.json from mirror url (eventually obtained from remote.json
      // or map.json) up MAX_META_BYTES. If the file is not available, or we have reached
      // MAX_UPDATES number of root metadata files go to step 5.3.10
      var newRootMaybe = metaFetcher.getRootAtVersion(nextVersion);
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
      trustedMetaStore.setRoot(trustedRoot);
      // 5.3.9) see if there are more versions go back 5.3.3
      nextVersion++;
    }

    // 5.3.10) Check expiration timestamp in trusted root is higher than fixed update start time,
    // otherwise throw error.
    ZonedDateTime expires = trustedRoot.getSignedMeta().getExpiresAsDate();
    throwIfExpired(expires);
    // 5.3.11) If the timestamp and / or snapshot keys have been rotated, then delete the trusted
    // timestamp and snapshot metadata files.
    if (hasNewKeys(
            preUpdateSnapshotRole, trustedRoot.getSignedMeta().getRoles().get(RootRole.SNAPSHOT))
        || hasNewKeys(
            preUpdateTimestampRole,
            trustedRoot.getSignedMeta().getRoles().get(RootRole.TIMESTAMP))) {
      trustedMetaStore.clearMetaDueToKeyRotation();
    }
  }

  private void throwIfExpired(ZonedDateTime expires) {
    if (expires.isBefore(updateStartTime)) {
      throw new RoleExpiredException(metaFetcher.getSource(), updateStartTime, expires);
    }
  }

  private boolean hasNewKeys(RootRole oldRole, RootRole newRole) {
    return !newRole.getKeyids().stream().allMatch(key -> oldRole.getKeyids().contains(key));
  }

  void verifyDelegate(Root trustedRoot, SignedTufMeta<? extends TufMeta> delegate)
      throws SignatureVerificationException, IOException, JsonParseException {
    verifyDelegate(
        delegate.getSignatures(),
        trustedRoot.getSignedMeta().getKeys(),
        trustedRoot.getSignedMeta().getRoles().get(delegate.getSignedMeta().getType()),
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
   * @throws IOException if an error occurred parsing a key
   */
  @VisibleForTesting
  void verifyDelegate(
      List<Signature> signatures,
      Map<String, Key> publicKeys,
      Role role,
      byte[] verificationMaterial)
      throws IOException {
    // use set to not count the same key multiple times towards the threshold.
    var goodSigs = new HashSet<>(role.getKeyids().size() * 4 / 3);
    // role.getKeyIds() defines the keys allowed to sign for this role.
    for (String keyid : role.getKeyids()) {
      List<Signature> matchingSignatures =
          signatures.stream()
              .filter(sig -> sig.getKeyId().equals(keyid))
              .collect(Collectors.toList());
      // check for any duplicate key_ids:
      // https://theupdateframework.github.io/specification/latest/#file-formats-object-format
      if (matchingSignatures.size() > 1) {
        throw new DuplicateKeyIdsException(matchingSignatures, keyid);
      }
      // only verify if we find a signature that matches an allowed key id.
      if (matchingSignatures.size() == 1) {
        var signature = matchingSignatures.get(0);
        // look for the public key that matches the key ID and use it for verification.
        var key = publicKeys.get(signature.getKeyId());
        if (key != null) {
          try {
            // while we error on keys that are not readable, we are intentionally more permissive
            // about signatures. If for ANY reason (except unparsed keys) we cannot validate a
            // signature, we continue as long as we find enough valid signatures within the
            // threshold. We still warn the user as this could be an indicator of data issues
            byte[] signatureBytes = Hex.decode(signature.getSignature());
            if (verifiers.newVerifier(key).verify(verificationMaterial, signatureBytes)) {
              goodSigs.add(signature.getKeyId());
            } else {
              log.log(
                  Level.FINE,
                  () ->
                      String.format(
                          Locale.ROOT,
                          "TUF: ignored failed signature verification: '%s' for keyid: '%s'",
                          signature.getSignature(),
                          signature.getKeyId()));
            }
          } catch (SignatureException e) {
            log.log(
                Level.FINE,
                () ->
                    String.format(
                        Locale.ROOT,
                        "TUF: ignored unverifiable signature: '%s' for keyid: '%s', because '%s'",
                        signature.getSignature(),
                        signature.getKeyId(),
                        e.getMessage()));
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

  void updateTimestamp()
      throws IOException,
          FileNotFoundException,
          SignatureVerificationException,
          JsonParseException {
    // 1) download the timestamp.json bytes.
    var timestamp =
        metaFetcher
            .getMeta(RootRole.TIMESTAMP, Timestamp.class)
            .orElseThrow(() -> new FileNotFoundException("timestamp.json", metaFetcher.getSource()))
            .getMetaResource();

    // 2) verify against threshold of keys as specified in trusted root.json
    verifyDelegate(trustedMetaStore.getRoot(), timestamp);

    // 3) If the new timestamp file has a lesser version than our current trusted timestamp file
    // report a rollback attack.  If it is equal, just return the original timestamp there should
    // be no changes. If it is higher than continue update.
    Optional<Timestamp> localTimestampMaybe = trustedMetaStore.findTimestamp();
    if (localTimestampMaybe.isPresent()) {
      Timestamp localTimestamp = localTimestampMaybe.get();
      if (localTimestamp.getSignedMeta().getVersion() > timestamp.getSignedMeta().getVersion()) {
        throw new RollbackVersionException(
            localTimestamp.getSignedMeta().getVersion(), timestamp.getSignedMeta().getVersion());
      }

      // The snapshot version in the new timestamp must not be smaller than snapshot
      // version in current timestamp
      var snapshotVersion = timestamp.getSignedMeta().getSnapshotMeta().getVersion();
      var localSnapshotVersion = localTimestamp.getSignedMeta().getSnapshotMeta().getVersion();
      if (snapshotVersion < localSnapshotVersion) {
        throw new RollbackVersionException(localSnapshotVersion, snapshotVersion);
      }

      if (localTimestamp.getSignedMeta().getVersion() == timestamp.getSignedMeta().getVersion()) {
        return;
      }
    }
    // 4) check expiration timestamp is after tuf update start time, else fail.
    throwIfExpired(timestamp.getSignedMeta().getExpiresAsDate());
    // 5) persist timestamp.json
    trustedMetaStore.setTimestamp(timestamp);
  }

  void updateSnapshot()
      throws IOException,
          FileNotFoundException,
          InvalidHashesException,
          SignatureVerificationException,
          JsonParseException {
    // 1) download the snapshot.json bytes up to timestamp's snapshot length.
    int timestampSnapshotVersion =
        trustedMetaStore.getTimestamp().getSignedMeta().getSnapshotMeta().getVersion();
    var snapshotResult =
        metaFetcher.getMeta(
            RootRole.SNAPSHOT,
            timestampSnapshotVersion,
            Snapshot.class,
            trustedMetaStore.getTimestamp().getSignedMeta().getSnapshotMeta().getLengthOrDefault());
    if (snapshotResult.isEmpty()) {
      throw new FileNotFoundException(
          timestampSnapshotVersion + ".snapshot.json", metaFetcher.getSource());
    }
    // 2) check against timestamp.snapshot.hash, this is optional, the fallback is
    // that the version must match, which is handled in (4).
    var snapshot = snapshotResult.get();
    if (trustedMetaStore.getTimestamp().getSignedMeta().getSnapshotMeta().getHashes().isPresent()) {
      verifyHashes(
          "snapshot",
          snapshot.getRawBytes(),
          trustedMetaStore.getTimestamp().getSignedMeta().getSnapshotMeta().getHashes().get());
    }
    // 3) Check against threshold of root signing keys, else fail
    verifyDelegate(trustedMetaStore.getRoot(), snapshot.getMetaResource());
    // 4) Check snapshot.version matches timestamp.snapshot.version, else fail.
    int snapshotVersion = snapshot.getMetaResource().getSignedMeta().getVersion();
    if (snapshotVersion != timestampSnapshotVersion) {
      throw new SnapshotVersionMismatchException(timestampSnapshotVersion, snapshotVersion);
    }
    // 5) Ensure all targets and delegated targets in the trusted (old) snapshots file have versions
    // which are less than or equal to the equivalent target in the new file.  Check that no targets
    // are missing in new file. Else fail.
    var trustedSnapshotMaybe = trustedMetaStore.findSnapshot();
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
    trustedMetaStore.setSnapshot(snapshot.getMetaResource());
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

  void updateTargets()
      throws IOException,
          FileNotFoundException,
          InvalidHashesException,
          SignatureVerificationException,
          FileExceedsMaxLengthException,
          JsonParseException {
    // 1) download the targets.json up to targets.json length in bytes.
    SnapshotMeta.SnapshotTarget targetMeta =
        trustedMetaStore.getSnapshot().getSignedMeta().getTargetMeta("targets.json");
    var targetsResultMaybe =
        metaFetcher.getMeta(
            RootRole.TARGETS,
            targetMeta.getVersion(),
            Targets.class,
            targetMeta.getLengthOrDefault());
    if (targetsResultMaybe.isEmpty()) {
      throw new FileNotFoundException(
          targetMeta.getVersion() + ".targets.json", metaFetcher.getSource());
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
    verifyDelegate(trustedMetaStore.getRoot(), targetsResult.getMetaResource());
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
    trustedMetaStore.setTargets(targetsResult.getMetaResource());
  }

  void downloadTarget(String targetName, TargetData targetData) throws IOException {
    var calculatedName = targetName;
    var calculatedPath = "";
    // if target name includes directories then we have to process the path
    if (targetName.contains("/")) {
      var targetPath = Paths.get(targetName);
      calculatedName = targetPath.getFileName().toString();
      calculatedPath = targetPath.getParent().toString();
      if (!calculatedPath.endsWith("/")) {
        calculatedPath = calculatedPath + "/";
      }
    }
    // 9) Download target up to length specified in bytes. verify against hash.
    String versionedTargetName;
    if (targetData.getHashes().getSha512() != null) {
      versionedTargetName =
          calculatedPath + targetData.getHashes().getSha512() + "." + calculatedName;
    } else {
      versionedTargetName =
          calculatedPath + targetData.getHashes().getSha256() + "." + calculatedName;
    }

    var targetBytes = targetFetcher.fetchResource(versionedTargetName, targetData.getLength());
    if (targetBytes == null) {
      throw new FileNotFoundException(targetName, targetFetcher.getSource());
    }
    verifyHashes(targetName, targetBytes, targetData.getHashes());

    // when persisting targets use the targetname without sha512 prefix
    // https://theupdateframework.github.io/specification/latest/index.html#fetch-target
    targetStore.writeTarget(targetName, targetBytes);
  }

  /**
   * Check whether a target name falls within the scope of a delegation role. Per the TUF spec,
   * roles use either {@code paths} (glob patterns) or {@code path_hash_prefixes} (hex prefix match
   * on SHA-256 of target name), but not both.
   */
  @VisibleForTesting
  boolean isTargetInRole(DelegationRole role, String targetName) {
    List<String> paths = role.getPaths();
    List<String> prefixes = role.getPathHashPrefixes();

    boolean hasPaths = !paths.isEmpty();
    boolean hasPrefixes = !prefixes.isEmpty();

    if (!hasPaths && !hasPrefixes) {
      return false;
    }

    // Per TUF spec, paths and path_hash_prefixes are mutually exclusive.
    // We check whichever is present; if both are present (invalid metadata),
    // we require both to match as a conservative choice.
    if (hasPaths) {
      boolean pathMatched = false;
      for (String pattern : paths) {
        if (matches(targetName, pattern)) {
          pathMatched = true;
          break;
        }
      }
      if (!pathMatched) {
        return false;
      }
    }

    if (hasPrefixes) {
      String targetHash =
          Hashing.sha256().hashString(targetName, StandardCharsets.UTF_8).toString();
      boolean hashMatched = false;
      for (String prefix : prefixes) {
        if (targetHash.startsWith(prefix.toLowerCase(Locale.ROOT))) {
          hashMatched = true;
          break;
        }
      }
      if (!hashMatched) {
        return false;
      }
    }

    return true;
  }

  @VisibleForTesting
  static boolean matches(String targetName, String pattern) {
    // Convert TUF glob to regex
    // * -> [^/]*
    // ? -> [^/]
    // everything else escaped
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < pattern.length(); i++) {
      char c = pattern.charAt(i);
      if (c == '*') {
        sb.append("[^/]*");
      } else if (c == '?') {
        sb.append("[^/]");
      } else if (".[]{}()\\^$+|".indexOf(c) != -1) {
        sb.append('\\').append(c);
      } else {
        sb.append(c);
      }
    }
    return targetName.matches(sb.toString());
  }

  private static class PendingDelegation {
    final DelegationRole role;
    final Targets parent;

    PendingDelegation(DelegationRole role, Targets parent) {
      this.role = role;
      this.parent = parent;
    }
  }

  /**
   * Iterative preorder depth-first walk of the delegation tree, matching Python TUF's
   * _preorder_depth_first_walk. Limits total delegations visited (not just depth) and tracks
   * visited roles to prevent cycles. Metadata is loaded lazily when a role is popped from the
   * stack.
   */
  private Optional<TargetData> findTargetData(String targetName, Targets topLevelTargets)
      throws IOException, JsonParseException {
    var visitedRoleNames = new HashSet<String>();
    var delegationsToVisit = new ArrayList<PendingDelegation>();

    // Check top-level targets first, then seed the stack with its delegations
    TargetData topData = topLevelTargets.getSignedMeta().getTargets().get(targetName);
    if (topData != null) {
      return Optional.of(topData);
    }
    visitedRoleNames.add(RootRole.TARGETS);
    pushChildDelegations(targetName, topLevelTargets, delegationsToVisit);

    while (visitedRoleNames.size() <= MAX_DELEGATIONS && !delegationsToVisit.isEmpty()) {
      var current = delegationsToVisit.remove(delegationsToVisit.size() - 1);
      String roleName = current.role.getName();

      // Skip visited roles to prevent cycles
      if (visitedRoleNames.contains(roleName)) {
        continue;
      }

      Targets currentTargets;
      try {
        currentTargets = updateDelegatedTargets(current.role, current.parent);
      } catch (SnapshotTargetMissingException | FileNotFoundException e) {
        log.log(
            Level.FINE,
            "TUF: Delegated targets metadata for role {0} not found, skipping: {1}",
            new Object[] {roleName, e.getMessage()});
        continue;
      } catch (SignatureVerificationException | RoleExpiredException e) {
        log.log(
            Level.FINE,
            "TUF: Delegated targets metadata for role {0} is invalid, skipping: {1}",
            new Object[] {roleName, e.getMessage()});
        continue;
      }

      // Check if target is in current role's targets
      TargetData data = currentTargets.getSignedMeta().getTargets().get(targetName);
      if (data != null) {
        return Optional.of(data);
      }

      // Mark as visited after checking targets (matches Python behavior)
      visitedRoleNames.add(roleName);
      pushChildDelegations(targetName, currentTargets, delegationsToVisit);
    }

    if (!delegationsToVisit.isEmpty()) {
      log.log(
          Level.WARNING,
          "TUF: {0} roles left to visit but max delegations ({1}) reached while searching for {2}",
          new Object[] {delegationsToVisit.size(), MAX_DELEGATIONS, targetName});
    }

    return Optional.empty();
  }

  /**
   * Pushes child delegations from {@code targets} onto {@code delegationsToVisit} for roles that
   * match {@code targetName}. Pushes in reverse order so the first matching role is on top of the
   * stack. Clears the stack if a terminating role is encountered.
   */
  private void pushChildDelegations(
      String targetName, Targets targets, List<PendingDelegation> delegationsToVisit)
      throws JsonParseException {
    var delegationsMaybe = targets.getSignedMeta().getDelegations();
    if (delegationsMaybe.isEmpty()) {
      return;
    }
    var children = new ArrayList<PendingDelegation>();
    for (DelegationRole role : delegationsMaybe.get().getRoles()) {
      if (!isTargetInRole(role, targetName)) {
        continue;
      }
      children.add(new PendingDelegation(role, targets));
      if (role.isTerminating()) {
        delegationsToVisit.clear();
        break;
      }
    }
    // Push in reverse so first child is on top of stack (popped first)
    Collections.reverse(children);
    delegationsToVisit.addAll(children);
  }

  private Targets updateDelegatedTargets(DelegationRole role, Targets parent)
      throws IOException, JsonParseException {
    String roleName = role.getName();
    SnapshotMeta.SnapshotTarget snapshotTarget =
        trustedMetaStore.getSnapshot().getSignedMeta().getMeta().get(roleName + ".json");
    if (snapshotTarget == null) {
      throw new SnapshotTargetMissingException(roleName + ".json");
    }

    Optional<Targets> localTargets = trustedMetaStore.findTargets(roleName);
    if (localTargets.isPresent()) {
      if (localTargets.get().getSignedMeta().getVersion() == snapshotTarget.getVersion()) {
        return localTargets.get();
      }
      if (localTargets.get().getSignedMeta().getVersion() > snapshotTarget.getVersion()) {
        throw new SnapshotTargetVersionException(
            roleName, snapshotTarget.getVersion(), localTargets.get().getSignedMeta().getVersion());
      }
    }

    // Fetch from remote
    var targetsResultMaybe =
        metaFetcher.getMeta(
            roleName,
            snapshotTarget.getVersion(),
            Targets.class,
            snapshotTarget.getLengthOrDefault());

    if (targetsResultMaybe.isEmpty()) {
      throw new FileNotFoundException(roleName + ".json", metaFetcher.getSource());
    }
    var targetsResult = targetsResultMaybe.get();

    // Verify hash
    if (snapshotTarget.getHashes().isPresent()) {
      verifyHashes(
          roleName + ".json", targetsResult.getRawBytes(), snapshotTarget.getHashes().get());
    }

    // Verify against parent's delegation keys/threshold
    Delegations parentDelegations =
        parent
            .getSignedMeta()
            .getDelegations()
            .orElseThrow(
                () ->
                    new IllegalStateException(
                        "Parent targets metadata has no delegations for role: " + role.getName()));
    verifyDelegate(
        targetsResult.getMetaResource().getSignatures(),
        parentDelegations.getKeys(),
        role,
        targetsResult.getMetaResource().getCanonicalSignedBytes());

    // Check version matches snapshot
    if (targetsResult.getMetaResource().getSignedMeta().getVersion()
        != snapshotTarget.getVersion()) {
      throw new SnapshotVersionMismatchException(
          snapshotTarget.getVersion(),
          targetsResult.getMetaResource().getSignedMeta().getVersion());
    }

    // Check expiration
    throwIfExpired(targetsResult.getMetaResource().getSignedMeta().getExpiresAsDate());

    // Persist
    trustedMetaStore.setTargets(roleName, targetsResult.getMetaResource());

    return targetsResult.getMetaResource();
  }

  @VisibleForTesting
  TargetStore getTargetStore() {
    return targetStore;
  }

  @VisibleForTesting
  TrustedMetaStore getMetaStore() {
    return trustedMetaStore;
  }

  public static class Builder {
    private Clock clock = Clock.systemUTC();
    private Verifiers.Supplier verifiers = Verifiers::newVerifier;

    private MetaFetcher metaFetcher;
    private Fetcher targetFetcher;
    private RootProvider trustedRootPath;
    private TrustedMetaStore trustedMetaStore;
    private TargetStore targetStore;

    public Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder setVerifiers(Verifiers.Supplier verifiers) {
      this.verifiers = verifiers;
      return this;
    }

    public Builder setTrustedMetaStore(TrustedMetaStore trustedMetaStore) {
      this.trustedMetaStore = trustedMetaStore;
      return this;
    }

    public Builder setTargetStore(TargetStore targetStore) {
      this.targetStore = targetStore;
      return this;
    }

    public Builder setTrustedRootPath(RootProvider trustedRootPath) {
      this.trustedRootPath = trustedRootPath;
      return this;
    }

    public Builder setMetaFetcher(MetaFetcher metaFetcher) {
      this.metaFetcher = metaFetcher;
      return this;
    }

    public Builder setTargetFetcher(Fetcher fetcher) {
      this.targetFetcher = fetcher;
      return this;
    }

    public Updater build() {
      return new Updater(
          clock,
          verifiers,
          metaFetcher,
          targetFetcher,
          trustedRootPath,
          trustedMetaStore,
          targetStore);
    }
  }
}
