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
import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.tuf.model.*;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tuf Client. Will eventually support configuring multiple remote mirrors and trust roots and
 * mapping to specific targets.
 *
 * @see <a
 *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">TUF
 *     client workflow</a>
 */
public class TufClient {

  private static final int MAX_UPDATES =
      1024; // Limit the update loop to retrieve a max of 1024 subsequent versions as expressed in
  // 5.3.3 of spec.

  private Clock clock;
  private Verifiers.Supplier verifiers;

  private Function<URL, MetaFetcher> fetcherSupplier;

  TufClient(Clock clock, Verifiers.Supplier verifiers, Function<URL, MetaFetcher> fetcherSupplier) {
    this.clock = clock;
    this.verifiers = verifiers;
    this.fetcherSupplier = fetcherSupplier;
  }

  private ZonedDateTime updateStartTime;

  // https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
  public void updateRoot(Path trustedRootPath, URL mirror, TufLocalStore localStore)
      throws IOException, RootExpiredException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidKeyException, MetaFileExceedsMaxException, RoleVersionException,
          SignatureVerificationException {
    var fetcher = fetcherSupplier.apply(mirror);
    // 5.3.1) record the time at start and use for expiration checks consistently throughout the
    // update.
    updateStartTime = ZonedDateTime.now(clock);

    // 5.3.2) load the trust metadata file (root.json), get version of root.json and the role
    // signature threshold value

    Root trustedRoot = GSON.get().fromJson(Files.readString(trustedRootPath), Root.class);
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
      var newRoot = newRootMaybe.get();
      // 5.3.4) we have a valid next version of the root.json. Check that the file has been signed
      // by:
      //   a) a threshold (from step 2) of keys specified in the trusted metadata
      //   b) and a threshold of keys in the new root.json.
      //    Fail if either a or b aren't true.
      var trustedRootKeys = trustedRoot.getSignedMeta().getKeys();
      var newRootSignatures = newRoot.getSignatures();
      byte[] newRootMetaBytes = newRoot.getCanonicalSignedBytes();
      // Verify our new root meta against the trusted root keys.
      RootRole trustedRootRoleMeta = trustedRoot.getSignedMeta().getRole(Role.Name.ROOT);
      verifyDelegate(newRootSignatures, trustedRootKeys, trustedRootRoleMeta, newRootMetaBytes);

      var newRootRoleMeta = newRoot.getSignedMeta().getRole(Role.Name.ROOT);
      var newRootKeys = newRoot.getSignedMeta().getKeys();
      // Verify our new root meta against the new root keys.
      verifyDelegate(newRootSignatures, newRootKeys, newRootRoleMeta, newRootMetaBytes);

      // 5.3.5) We've taken the liberty to modify 5.3.5 to just validate that the new root meta
      // matches the version we pulled based off of the pattern {version}.root.json. We know due to
      // the loop constraints that it is larger than the current version.
      if (newRoot.getSignedMeta().getVersion() != nextVersion) {
        throw new RoleVersionException(nextVersion, newRoot.getSignedMeta().getVersion());
      }
      // 5.3.7) set the trusted root metadata to the new root
      trustedRoot = newRoot;
      // 5.3.8) persist to repo
      localStore.setTrustedRoot(trustedRoot);
      // 5.3.9) see if there are more versions go back 5.3.3
      nextVersion++;
    }

    // 5.3.10) Check expiration timestamp in trusted root is higher than fixed update start time,
    // otherwise throw error.
    ZonedDateTime expires = trustedRoot.getSignedMeta().getExpiresAsDate();
    if (expires.isBefore(updateStartTime)) {
      throw new RootExpiredException(mirror.toString(), updateStartTime, expires);
    }
    // 5.3.11) If the timestamp and / or snapshot keys have been rotated, then delete the trusted
    // timestamp and snapshot metadata files.
    if (hasNewKeys(preUpdateSnapshotRole, trustedRoot.getSignedMeta().getRole(Role.Name.SNAPSHOT))
        || hasNewKeys(
            preUpdateTimestampRole, trustedRoot.getSignedMeta().getRole(Role.Name.TIMESTAMP))) {
      localStore.clearMetaDueToKeyRotation();
    }
  }

  private boolean hasNewKeys(RootRole oldRole, RootRole newRole) {
    return newRole.getKeyids().stream().allMatch(s -> oldRole.getKeyids().contains(s));
  }

  /**
   * Verifies that a delegate role has been signed by the threshold amount of keys.
   *
   * @param signatures these are the signatures on the role meta we're verifying
   * @param publicKeys a map of key IDs to public keys used for signing various roles
   * @param role the key ids and threshold values for role signing
   * @throws SignatureVerificationException if there are not enough verified signatures
   */
  @VisibleForTesting
  void verifyDelegate(
      List<Signature> signatures,
      Map<String, Key> publicKeys,
      Role role,
      byte[] verificationMaterial)
      throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException,
          InvalidKeySpecException {
    // use set to not count the same key multiple times towards the threshold.
    var goodSigs = new HashSet<>(role.getKeyids().size() * 4 / 3);
    // role.getKeyIds() defines the keys allowed to sign for this role.
    for (String keyid : role.getKeyids()) {
      Optional<Signature> signatureMaybe =
          signatures.stream().filter(sig -> sig.getKeyId().equals(keyid)).findFirst();
      // only verify if we find a signature that matcheds an allowed key id.
      if (signatureMaybe.isPresent()) {
        var signature = signatureMaybe.get();
        // look for the public key that matches the key ID and use it for verification.
        var key = publicKeys.get(signature.getKeyId());
        if (key != null) {
          // key bytes are in Hex not Base64!
          // TODO(patrick): this will change in a subsequent version. Add code to handle PEM Encoded
          // keys as well.
          byte[] keyBytes = Hex.decode(key.getKeyVal().get("public"));
          var pubKey = Keys.constructTufPublicKey(keyBytes, key.getScheme());
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

  public void updateTimestamp() {
    // 1) download the timestamp.json bytes up to few 10s of K max.

    // 2) verify against threshold of keys as specified in trusted root.json

    // 3) check that version of new timestamp.json is higher or equal than current, else fail.
    //     3.2) check that timestamp.snapshot.version <= timestamp.version or fail

    // 4) check expiration timestamp is after tuf update start time, else fail.

    // 5) persist timestamp.json
  }

  public void updateSnapshot() {
    // 1) download the snapshot.json bytes up to few 10s of K max.

    // 2) check against timestamp.snapshot.hash

    // 3) Check against threshold of root signing keys, else fail

    // 4) Check snapshot.version matches timestamp.snapshot.version, else fail.

    // 5) Ensure all targets and delegated targets in the trusted (old) snapshots file are less
    // than or equal to the equivalent target in the new file.  Check that no targets are missing
    // in new file. Else fail.

    // 6) Ensure expiration timestamp of snapshot is later than tuf update start time.

    // 7) persist snapshot.
  }

  public void updateTargets() {
    // 1) download the targets.json to max bytes

    // 2) check hash against snapshot.targets.hash, else fail.

    // 3) check against threshold of keys as specified by trusted root.json

    // 4) check targets.version == snapshot.targets.version, else fail.

    // 5) check expiration is after tuf update start time

    // 6) persist targets metadata

    // 7) starting at each top level target role:
    //        do pre-order DFS of metadata.
    //        skip already visited roles
    //        if maximum roles visited go to 8) downloading targets
    //        process delegations (not sure if we need this yet)

    // 8) If target is missing metadata fail.

    // 9) Download target up to length specified in bytes. verify against hash.

    // Done!!
  }

  public static class Builder {
    private Clock clock = Clock.systemUTC();
    private Verifiers.Supplier verifiers = Verifiers::newVerifier;
    private Function<URL, MetaFetcher> fetcherSupplier = HttpMetaFetcher::newFetcher;

    public Builder setClock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder setVerifiers(Verifiers.Supplier verifiers) {
      this.verifiers = verifiers;
      return this;
    }

    public Builder setFetcherSupplier(Function<URL, MetaFetcher> fetcherSupplier) {
      this.fetcherSupplier = fetcherSupplier;
      return this;
    }

    public TufClient build() {
      return new TufClient(clock, verifiers, fetcherSupplier);
    }
  }
}
