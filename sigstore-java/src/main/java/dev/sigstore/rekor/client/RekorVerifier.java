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
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.rekor.client.RekorEntry.Checkpoint;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import dev.sigstore.trustroot.TransparencyLogs;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.util.encoders.Hex;

/** Verifier for rekor entries. */
public class RekorVerifier {
  private final TransparencyLogs tlogs;

  public static RekorVerifier newRekorVerifier(SigstoreTrustedRoot trustRoot) {
    return newRekorVerifier(trustRoot.getTLogs());
  }

  public static RekorVerifier newRekorVerifier(TransparencyLogs tlogs) {
    return new RekorVerifier(tlogs);
  }

  private RekorVerifier(TransparencyLogs tlogs) {
    this.tlogs = tlogs;
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

    var tlog =
        tlogs
            .find(Hex.decode(entry.getLogID()), entry.getIntegratedTimeInstant())
            .orElseThrow(
                () ->
                    new RekorVerificationException(
                        "Log entry (logid, timestamp) does not match any provided transparency logs."));

    try {
      var verifier = Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey());
      if (!verifier.verify(
          entry.getSignableContent(),
          Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
        throw new RekorVerificationException("Entry SET was not valid");
      }
    } catch (InvalidKeySpecException ike) {
      throw new RekorVerificationException("Public Key could be parsed", ike);
    } catch (InvalidKeyException ike) {
      throw new RekorVerificationException("Public Key was invalid", ike);
    } catch (SignatureException se) {
      throw new RekorVerificationException("Signature was invalid", se);
    } catch (NoSuchAlgorithmException nsae) {
      throw new AssertionError("Required verification algorithm 'SHA256withECDSA' not found.");
    }

    // verify inclusion proof
    verifyInclusionProof(entry);
    verifyCheckpoint(entry, tlog);
  }

  /** Verify that a Rekor Entry is in the log by checking inclusion proof. */
  private void verifyInclusionProof(RekorEntry entry) throws RekorVerificationException {

    var inclusionProof = entry.getVerification().getInclusionProof();

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
    if (!calcuatedRootHash.equals(inclusionProof.getRootHash())) {
      throw new RekorVerificationException(
          "Calculated inclusion proof root hash does not match provided root hash\n"
              + calcuatedRootHash
              + "\n"
              + inclusionProof.getRootHash());
    }
  }

  private void verifyCheckpoint(RekorEntry entry, TransparencyLog tlog)
      throws RekorVerificationException {
    Checkpoint checkpoint;
    try {
      checkpoint = entry.getVerification().getInclusionProof().parsedCheckpoint();
    } catch (RekorParseException ex) {
      throw new RekorVerificationException("Could not parse checkpoint", ex);
    }

    byte[] inclusionRootHash =
        Hex.decode(entry.getVerification().getInclusionProof().getRootHash());
    byte[] checkpointRootHash = Base64.getDecoder().decode(checkpoint.getBase64Hash());

    if (!Arrays.equals(inclusionRootHash, checkpointRootHash)) {
      throw new RekorVerificationException(
          "Checkpoint root hash does not match root hash provided in inclusion proof");
    }
    var keyHash = Hashing.sha256().hashBytes(tlog.getPublicKey().getRawBytes()).asBytes();
    // checkpoint 0 is always the log, not any of the cross signing verifiers/monitors
    var sig = checkpoint.getSignatures().get(0);
    for (int i = 0; i < 4; i++) {
      if (sig.getKeyHint()[i] != keyHash[i]) {
        throw new RekorVerificationException(
            "Checkpoint key hint did not match provided log public key");
      }
    }
    try {
      Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey())
          .verifyDigest(inclusionRootHash, sig.getSignature());
    } catch (NoSuchAlgorithmException
        | InvalidKeySpecException
        | SignatureException
        | InvalidKeyException ex) {
      throw new RekorVerificationException("Could not verify checkpoint signature", ex);
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
