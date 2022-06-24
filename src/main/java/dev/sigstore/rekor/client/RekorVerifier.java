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
package dev.sigstore.rekor.client;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.common.hash.Hashing;
import dev.sigstore.encryption.Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.LinkedHashMap;
import org.bouncycastle.util.encoders.Hex;

/** Verifier for rekor entries. */
public class RekorVerifier {
  private final PublicKey rekorPublicKey;

  public static RekorVerifier newRekorVerifier(byte[] rekorPublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    // TODO: accept any keytime and appropriately initialize the signer below (currently only EC
    // compatible: https://github.com/sigstore/sigstore-java/issues/32)
    PublicKey publicKey = Keys.parsePublicKey(rekorPublicKey);
    return new RekorVerifier(publicKey);
  }

  private RekorVerifier(PublicKey rekorPublicKey) {
    this.rekorPublicKey = rekorPublicKey;
  }

  /**
   * Verify that a Rekor Entry is signed with the rekor public key loaded into this verifier
   *
   * @param entry the entry to verify
   * @throws RekorVerificationException if the entry cannot be verified
   */
  public void verifyEntry(RekorEntry entry)
      throws RekorVerificationException, NoSuchAlgorithmException, InvalidKeyException,
          SignatureException {
    if (entry.getVerification() == null) {
      throw new RekorVerificationException("No verification information in entry.");
    }

    if (entry.getVerification().getSignedEntryTimestamp() == null) {
      throw new RekorVerificationException("No signed entry timestamp found in entry.");
    }

    // use a LinkedHashMap to preserve order, json must be canonical
    // (https://datatracker.ietf.org/doc/html/rfc8785)
    var signableContent = new LinkedHashMap<String, Object>();
    signableContent.put("body", entry.getBody());
    signableContent.put("integratedTime", entry.getIntegratedTime());
    signableContent.put("logID", entry.getLogID());
    signableContent.put("logIndex", entry.getLogIndex());

    // TODO: I think we can verify the logID (sha256 of log public key) here too
    // to provide the user with some useful information
    // (https://github.com/sigstore/sigstore-java/issues/34)

    var signableJson = GSON.get().toJson(signableContent);

    // TODO: Verify more than just "ec" signed rekor entries
    // (https://github.com/sigstore/sigstore-java/issues/32)
    var verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(rekorPublicKey);
    verifier.update(signableJson.getBytes(StandardCharsets.UTF_8));
    if (!verifier.verify(
        Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
      throw new RekorVerificationException("Entry SET was not valid");
    }
  }

  /**
   * Verify that a Rekor Entry is in the log by checking inclusion proof.
   *
   * @param entry the entry to verify
   * @throws RekorVerificationException if the entry cannot be verified
   */
  public void verifyInclusionProof(RekorEntry entry) throws RekorVerificationException {

    var inclusionProof =
        entry
            .getVerification()
            .getInclusionProof()
            .orElseThrow(
                () ->
                    new RekorVerificationException(
                        "No inclusion proof was found in the rekor entry"));

    var leafHash =
        Hashing.sha256()
            .hashBytes(combineBytes(new byte[] {0x00}, Base64.getDecoder().decode(entry.getBody())))
            .asBytes();

    // see: https://datatracker.ietf.org/doc/rfc9162/ section 2.1.3.2

    // nodeIndex and totalNodes represent values for a specific level in the tree
    // starting at the leafs and moving up to the root.
    var nodeIndex = inclusionProof.getLogIndex();
    var totalNodes = inclusionProof.getTreeSize() - 1;

    var currentHash = leafHash;
    var hashes = inclusionProof.getHashes();

    for (var hash : hashes) {
      byte[] p = Hex.decode(hash);
      if (totalNodes == 0) {
        throw new RekorVerificationException("Inclusion proof failed, ended prematurely");
      }
      if (nodeIndex == totalNodes || nodeIndex % 2 == 1) {
        currentHash = hashChildren(p, currentHash);
        while (nodeIndex % 2 == 0) {
          nodeIndex = nodeIndex >> 1;
          totalNodes = totalNodes >> 1;
        }
      } else {
        currentHash = hashChildren(currentHash, p);
      }
      nodeIndex = nodeIndex >> 1;
      totalNodes = totalNodes >> 1;
    }

    var calcuatedRootHash = Hex.toHexString(currentHash);
    if (!calcuatedRootHash.equals(inclusionProof.rootHash())) {
      throw new RekorVerificationException(
          "Calculated inclusion proof root hash does not match provided root hash\n"
              + calcuatedRootHash
              + "\n"
              + inclusionProof.rootHash());
    }
  }

  private static byte[] combineBytes(byte[] first, byte[] second) {
    byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  // hash the concatination of 0x01, left and right
  private static byte[] hashChildren(byte[] left, byte[] right) {
    return Hashing.sha256()
        .hashBytes(combineBytes(new byte[] {0x01}, combineBytes(left, right)))
        .asBytes();
  }
}
