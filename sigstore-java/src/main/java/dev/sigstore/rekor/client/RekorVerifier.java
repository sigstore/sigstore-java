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
import dev.sigstore.UnsupportedAlgorithmException;
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
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.util.encoders.DecoderException;
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

    byte[] logId;
    try {
      logId = Hex.decode(entry.getLogID());
    } catch (DecoderException de) {
      throw new RekorVerificationException("Log entry (logid) is not a valid hex string.", de);
    }

    var tlog =
        TransparencyLog.find(tlogs, logId)
            .orElseThrow(
                () ->
                    new RekorVerificationException(
                        "Log entry (logid) does not match any provided transparency logs."));

    var set = entry.getVerification().getSignedEntryTimestamp();
    if (set != null && !set.isEmpty()) {
      byte[] decodedSet;
      try {
        decodedSet = Base64.getDecoder().decode(set);
      } catch (IllegalArgumentException e) {
        throw new RekorVerificationException("Entry SET is not valid base64", e);
      }
      try {
        var verifier = Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey());
        if (!verifier.verify(entry.getSignableContent(), decodedSet)) {
          throw new RekorVerificationException("Entry SET was not valid");
        }
      } catch (InvalidKeySpecException
          | InvalidKeyException
          | SignatureException
          | UnsupportedAlgorithmException
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

    byte[] bodyBytes;
    try {
      bodyBytes = Base64.getDecoder().decode(entry.getBody());
    } catch (IllegalArgumentException e) {
      throw new RekorVerificationException("Entry body is not valid base64", e);
    }

    var leafHash =
        Hashing.sha256().newHasher().putByte((byte) 0x00).putBytes(bodyBytes).hash().asBytes();

    List<byte[]> hashes = new ArrayList<>();
    byte[] expectedRootHash;
    try {
      for (String hash : inclusionProof.getHashes()) {
        hashes.add(Hex.decode(hash));
      }
      expectedRootHash = Hex.decode(inclusionProof.getRootHash());
    } catch (DecoderException e) {
      throw new RekorVerificationException("Inclusion proof contains invalid hex strings", e);
    }

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

    if (!Objects.equals(
        parsedCheckpoint.getSize(), entry.getVerification().getInclusionProof().getTreeSize())) {
      throw new RekorVerificationException(
          "Checkpoint tree size does not match tree size provided in inclusion proof");
    }

    byte[] inclusionRootHash;
    try {
      inclusionRootHash = Hex.decode(entry.getVerification().getInclusionProof().getRootHash());
    } catch (DecoderException e) {
      throw new RekorVerificationException(
          "Inclusion proof root hash is not a valid hex string", e);
    }

    byte[] checkpointRootHash;
    try {
      checkpointRootHash = Base64.getDecoder().decode(parsedCheckpoint.getBase64Hash());
    } catch (IllegalArgumentException e) {
      throw new RekorVerificationException("Checkpoint root hash is not valid base64", e);
    }

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
        | UnsupportedAlgorithmException
        | InvalidKeyException ex) {
      throw new RekorVerificationException("Could not verify checkpoint signature", ex);
    }
  }
}
