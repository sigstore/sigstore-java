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

import com.google.common.hash.Hashing;
import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.signers.Verifier;
import dev.sigstore.encryption.signers.Verifiers;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import org.bouncycastle.util.encoders.Hex;

/** Verifier for rekor entries. */
public class RekorVerifier {
  private final Verifier verifier;

  // A calculated logId from the transparency log (rekor) public key
  private final String calculatedLogId;

  public static RekorVerifier newRekorVerifier(byte[] rekorPublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    var publicKey = Keys.parsePublicKey(rekorPublicKey);
    var verifier = Verifiers.newVerifier(publicKey);

    return new RekorVerifier(verifier);
  }

  private RekorVerifier(Verifier verifier) {
    this.calculatedLogId =
        Hashing.sha256().hashBytes(verifier.getPublicKey().getEncoded()).toString();
    this.verifier = verifier;
  }

  /**
   * Verify that a Rekor Entry is signed with the rekor public key loaded into this verifier
   *
   * @param entry the entry to verify
   * @throws RekorVerificationException if the entry cannot be verified
   */
  public void verifyEntry(RekorEntry entry) throws RekorVerificationException {
    if (entry.getVerification() == null) {
      throw new RekorVerificationException("No verification information in entry.");
    }

    if (entry.getVerification().getSignedEntryTimestamp() == null) {
      throw new RekorVerificationException("No signed entry timestamp found in entry.");
    }

    if (!entry.getLogID().equals(calculatedLogId)) {
      throw new RekorVerificationException("LogId does not match supplied rekor public key.");
    }

    try {
      if (!verifier.verify(
          entry.getSignableContent(),
          Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
        throw new RekorVerificationException("Entry SET was not valid");
      }
    } catch (InvalidKeyException ike) {
      throw new RekorVerificationException("Public Key was invalid", ike);
    } catch (SignatureException se) {
      throw new RekorVerificationException("Signature was invalid", se);
    } catch (NoSuchAlgorithmException nsae) {
      throw new AssertionError("Required verification algorithm 'SHA256withECDSA' not found.");
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
