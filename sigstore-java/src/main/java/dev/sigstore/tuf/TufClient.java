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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.json.gson.GsonFactory;
import com.google.common.annotations.VisibleForTesting;
import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.tuf.model.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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
import org.bouncycastle.util.encoders.Hex;

/**
 * Tuf Client. Will eventually support configuring multiple remote mirrors and trust roots and
 * mapping to specific targets.
 */
public class TufClient {

  private static final int MAX_META_BYTES = 99 * 1024; // 99 KB
  private static final int MAX_UPDATES =
      1024; // Limit the update loop to retrieve a max of 1024 subsequent versions as expressed in
  // 5.3.3 of spec.

  protected Clock clock = Clock.systemUTC();

  private ZonedDateTime updateStartTime;

  // https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
  public void updateRoot(Path trustedRootPath, URL mirror, Path localStore)
      throws IOException, RootExpiredException, NoSuchAlgorithmException, InvalidKeySpecException,
          InvalidKeyException, MetaFileExceedsMaxException, RoleVersionException,
          SignatureVerificationException {
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
      String nextVersionFileName = nextVersion + ".root.json";
      GenericUrl nextVersionUrl = new GenericUrl(mirror + "/" + nextVersionFileName);
      var req =
          HttpClients.newHttpTransport(ImmutableHttpParams.builder().build())
              .createRequestFactory(
                  request -> {
                    request.setParser(GsonFactory.getDefaultInstance().createJsonObjectParser());
                  })
              .buildGetRequest(nextVersionUrl);
      req.getHeaders().setAccept("application/json; api-version=2.0");
      req.getHeaders().setContentType("application/json");
      req.setThrowExceptionOnExecuteError(false);
      var resp = req.execute();
      if (resp.getStatusCode() == 404) {
        // No newer versions, go to 5.3.10.
        break;
      }
      if (resp.getStatusCode() != 200) {
        throw new TufException(
            String.format(
                "Unexpected return from mirror. Status code: %s, status message: %s"
                    + resp.getStatusCode()
                    + resp.getStatusMessage()));
      }
      byte[] rootBytes = resp.getContent().readNBytes(MAX_META_BYTES);
      if (rootBytes.length == MAX_META_BYTES && resp.getContent().read() != -1) {
        throw new MetaFileExceedsMaxException(nextVersionUrl.toString(), MAX_META_BYTES);
      }
      var newRoot = GSON.get().fromJson(new String(rootBytes, StandardCharsets.UTF_8), Root.class);

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
      Path localTrustRoot = localStore.resolve("root.json");
      if (localTrustRoot.toFile().exists()) {
        // Backup the old root.
        Files.move(localTrustRoot, localStore.resolve((nextVersion - 1) + ".root.json"));
      }
      try (FileWriter fileWriter = new FileWriter(localTrustRoot.toFile())) {
        fileWriter.write(GSON.get().toJson(trustedRoot));
      }
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
      File snapshotMetaFile = localStore.resolve("snapshot.json").toFile();
      if (snapshotMetaFile.exists()) {
        Files.delete(snapshotMetaFile.toPath());
      }
      File timestampMetaFile = localStore.resolve("timestamp.json").toFile();
      if (timestampMetaFile.exists()) {
        Files.delete(timestampMetaFile.toPath());
      }
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
  static void verifyDelegate(
      List<Signature> signatures,
      Map<String, Key> publicKeys,
      Role role,
      byte[] verificationMaterial)
      throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException,
          InvalidKeySpecException {
    // use set to not count the same key multiple times towards the threshold.
    var goodSigs = new HashSet<>(role.getKeyids().size());
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
          // TODO(patrick): this will change in a subsequent version. Add code to handle PEM Encoded keys as well.
          byte[] keyBytes = Hex.decode(key.getKeyVal().get("public"));
          var pubKey = Keys.constructTufPublicKey(keyBytes, key.getScheme());
          byte[] signatureBytes = Hex.decode(signature.getSignature());
          try {
            if (Verifiers.newVerifier(pubKey).verify(verificationMaterial, signatureBytes)) {
              goodSigs.add(signature.getKeyId());
            }
          } catch (SignatureException e) {
            throw new RuntimeException(e);
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

    // 2) verify against threshold of keys as specified in trusted root,json

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
}
