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
import dev.sigstore.merkle.InclusionProofVerificationException;
import dev.sigstore.merkle.InclusionProofVerifier;
import dev.sigstore.rekor.client.RekorEntry.Checkpoint;
import dev.sigstore.rekor.client.RekorEntry.CheckpointSignature;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.util.encoders.Hex;

/** Verifier for rekor entries. */
public class RekorVerifier {
  private final List<TransparencyLog> tlogs;

  public static RekorVerifier newRekorVerifier(SigstoreTrustedRoot trustRoot) {
    return newRekorVerifier(trustRoot.getTLogs());
  }

  public static RekorVerifier newRekorVerifier(List<TransparencyLog> tlogs) {
    return new RekorVerifier(tlogs);
  }

  private RekorVerifier(List<TransparencyLog> tlogs) {
    this.tlogs = tlogs;
  }

  /**
   * Verifies a Rekor entry by checking the inclusion proof and checkpoint against the configured
   * transparency logs. For v1 entries, it also verifies the Signed Entry Timestamp (SET).
   *
   * @param entry The RekorEntry to verify.
   * @throws RekorVerificationException if the entry cannot be verified for any reason, such as an
   *     invalid proof or signature.
   */
  public void verifyEntry(RekorEntry entry) throws RekorVerificationException {
    if (entry.getVerification().getInclusionProof() == null) {
      throw new RekorVerificationException("No inclusion proof in entry.");
    }

    var tlog =
        TransparencyLog.find(tlogs, Hex.decode(entry.getLogID()))
            .orElseThrow(
                () ->
                    new RekorVerificationException(
                        "Log entry (logid) does not match any provided transparency logs."));

    var set = entry.getVerification().getSignedEntryTimestamp();
    if (set != null && !set.isEmpty()) {
      try {
        var verifier = Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey());
        if (!verifier.verify(
            entry.getSignableContent(),
            Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
          throw new RekorVerificationException("Entry SET was not valid");
        }
      } catch (InvalidKeySpecException
          | InvalidKeyException
          | SignatureException
          | NoSuchAlgorithmException e) {
        throw new RekorVerificationException("Entry SET verification failed: " + e.getMessage(), e);
      }
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
            .newHasher()
            .putByte((byte) 0x00)
            .putBytes(Base64.getDecoder().decode(entry.getBody()))
            .hash()
            .asBytes();

    List<byte[]> hashes = new ArrayList<>();
    for (String hash : inclusionProof.getHashes()) {
      hashes.add(Hex.decode(hash));
    }

    byte[] expectedRootHash = Hex.decode(inclusionProof.getRootHash());

    try {
      InclusionProofVerifier.verify(
          leafHash,
          inclusionProof.getLogIndex(),
          inclusionProof.getTreeSize(),
          hashes,
          expectedRootHash);
    } catch (InclusionProofVerificationException e) {
      throw new RekorVerificationException("Inclusion proof verification failed", e);
    }
  }

  private void verifyCheckpoint(RekorEntry entry, TransparencyLog tlog)
      throws RekorVerificationException {
    Checkpoint parsedCheckpoint;
    try {
      parsedCheckpoint = entry.getVerification().getInclusionProof().parsedCheckpoint();
    } catch (RekorParseException ex) {
      throw new RekorVerificationException("Could not parse checkpoint from envelope", ex);
    }

    final int MAX_CHECKPOINT_SIGNATURES = 20;
    if (parsedCheckpoint.getSignatures().size() > MAX_CHECKPOINT_SIGNATURES) {
      throw new RekorVerificationException(
          "Checkpoint contains an excessive number of signatures ("
              + parsedCheckpoint.getSignatures().size()
              + "), exceeding the maximum allowed of "
              + MAX_CHECKPOINT_SIGNATURES);
    }

    byte[] inclusionRootHash =
        Hex.decode(entry.getVerification().getInclusionProof().getRootHash());
    byte[] checkpointRootHash = Base64.getDecoder().decode(parsedCheckpoint.getBase64Hash());

    if (!Arrays.equals(inclusionRootHash, checkpointRootHash)) {
      throw new RekorVerificationException(
          "Checkpoint root hash does not match root hash provided in inclusion proof");
    }

    Optional<CheckpointSignature> matchingSig =
        parsedCheckpoint.getSignatures().stream()
            .filter(sig -> sig.getIdentity().equals(tlog.getBaseUrl().getHost()))
            .findFirst();

    if (!matchingSig.isPresent()) {
      throw new RekorVerificationException(
          "No matching checkpoint signature found for transparency log: "
              + tlog.getBaseUrl().getHost());
    }

    var keyId = tlog.getLogId().getKeyId();
    var keyHint = Arrays.copyOfRange(keyId, 0, 4);
    if (!Arrays.equals(matchingSig.get().getKeyHint(), keyHint)) {
      throw new RekorVerificationException(
          "Checkpoint key hint did not match provided log public key");
    }

    var signedData = parsedCheckpoint.getSignedData();

    try {
      if (!Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey())
          .verify(signedData.getBytes(StandardCharsets.UTF_8), matchingSig.get().getSignature())) {
        throw new RekorVerificationException("Checkpoint signature was invalid");
      }
    } catch (NoSuchAlgorithmException
        | InvalidKeySpecException
        | SignatureException
        | InvalidKeyException ex) {
      throw new RekorVerificationException("Could not verify checkpoint signature", ex);
    }
  }
}
