/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.rekor.v2.client;

import com.google.common.hash.Hashing;
import com.google.protobuf.ByteString;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.merkle.InclusionProofVerificationException;
import dev.sigstore.merkle.InclusionProofVerifier;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.rekor.client.Checkpoints;
import dev.sigstore.rekor.client.RekorEntry.Checkpoint;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/* Verifier for rekor v2 entries. */
public class RekorV2Verifier {
  private final List<TransparencyLog> tlogs;

  public static RekorV2Verifier newRekorV2Verifier(SigstoreTrustedRoot trustRoot) {
    return newRekorV2Verifier(trustRoot.getTLogs());
  }

  public static RekorV2Verifier newRekorV2Verifier(List<TransparencyLog> tlogs) {
    return new RekorV2Verifier(tlogs);
  }

  private RekorV2Verifier(List<TransparencyLog> tlogs) {
    this.tlogs = tlogs;
  }

  public void verifyEntry(TransparencyLogEntry entry, Instant timestamp)
      throws RekorVerificationException {
    if (entry.getInclusionProof() == null) {
      throw new RekorVerificationException("No inclusion proof in entry.");
    }

    var tlog =
        TransparencyLog.find(tlogs, entry.getLogId().getKeyId().toByteArray(), timestamp)
            .orElseThrow(
                () ->
                    new RekorVerificationException(
                        "Log entry (logid, timestamp) does not match any provided transparency logs."));

    // verify inclusion proof
    verifyInclusionProof(entry);
    verifyCheckpoint(entry, tlog);
  }

  /** Verify that a Rekor Entry is in the log by checking inclusion proof. */
  private void verifyInclusionProof(TransparencyLogEntry entry) throws RekorVerificationException {
    var inclusionProof = entry.getInclusionProof();

    var leafHash =
        Hashing.sha256()
            .hashBytes(
                InclusionProofVerifier.combineBytes(
                    new byte[] {0x00}, entry.getCanonicalizedBody().toByteArray()))
            .asBytes();

    List<byte[]> hashes = new ArrayList<>();
    for (ByteString hash : inclusionProof.getHashesList()) {
      hashes.add(hash.toByteArray());
    }

    byte[] expectedRootHash = inclusionProof.getRootHash().toByteArray();

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

  private void verifyCheckpoint(TransparencyLogEntry entry, TransparencyLog tlog)
      throws RekorVerificationException {
    var checkpoint = entry.getInclusionProof().getCheckpoint();
    Checkpoint parsedCheckpoint;
    try {
      parsedCheckpoint = Checkpoints.from(checkpoint.getEnvelope());
    } catch (RekorParseException ex) {
      throw new RekorVerificationException("Could not parse checkpoint from envelope", ex);
    }

    byte[] inclusionRootHash = entry.getInclusionProof().getRootHash().toByteArray();
    byte[] checkpointRootHash = Base64.getDecoder().decode(parsedCheckpoint.getBase64Hash());

    if (!Arrays.equals(inclusionRootHash, checkpointRootHash)) {
      throw new RekorVerificationException(
          "Checkpoint root hash does not match root hash provided in inclusion proof");
    }
    var keyHash = tlog.getLogId().getKeyId();
    // checkpoint 0 is always the log, not any of the cross signing verifiers/monitors
    var sig = parsedCheckpoint.getSignatures().get(0);
    for (int i = 0; i < 4; i++) {
      if (sig.getKeyHint()[i] != keyHash[i]) {
        throw new RekorVerificationException(
            "Checkpoint key hint did not match provided log public key");
      }
    }
    var signedData = parsedCheckpoint.getSignedData();

    try {
      if (!Verifiers.newVerifier(tlog.getPublicKey().toJavaPublicKey())
          .verify(signedData.getBytes(StandardCharsets.UTF_8), sig.getSignature())) {
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
