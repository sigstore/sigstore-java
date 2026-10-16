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

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import com.google.protobuf.InvalidProtocolBufferException;
import dev.sigstore.json.GsonSupplier;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RekorVerifierTest {
  public static SigstoreTrustedRoot trustRoot;
  public static String entryV1;
  public static String entryV2;

  @BeforeEach
  public void loadResources() throws IOException {
    entryV1 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/entry.json"),
            StandardCharsets.UTF_8);
    entryV2 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/entry-v2.json"),
            StandardCharsets.UTF_8);
  }

  @BeforeAll
  public static void initTrustRoot() throws Exception {
    trustRoot =
        SigstoreTrustedRoot.from(
            Resources.getResource("dev/sigstore/trustroot/staging_trusted_root.json").openStream());
  }

  @Test
  public void verifyEntry_v1() throws Exception {
    var rekorEntry = getV1RekorEntry(entryV1);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    verifier.verifyEntry(rekorEntry);
  }

  @Test
  public void verifyEntry_v1_invalidSet() throws Exception {
    var invalidV1Entry = entryV1.replace("\"logIndex\": 1688", "\"logIndex\": 1700");
    var rekorEntry = getV1RekorEntry(invalidV1Entry);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals("Entry SET was not valid", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v1_unverifiableSet_badSignature() throws Exception {
    var rekorEntry = getV1RekorEntry(entryV1);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    // create a new entry with a SET that is not a valid signature
    var verification =
        ImmutableVerification.builder()
            .from(rekorEntry.getVerification())
            .signedEntryTimestamp("aW52YWxpZCBzaWduYXR1cmU=") // "invalid signature" in base64
            .build();
    var entryWithInvalidSet =
        ImmutableRekorEntry.builder().from(rekorEntry).verification(verification).build();

    // The verifier should fail when trying to parse the signature
    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(entryWithInvalidSet));
    Assertions.assertTrue(thrown.getMessage().startsWith("Entry SET verification failed:"));
    Assertions.assertInstanceOf(SignatureException.class, thrown.getCause());
  }

  @Test
  public void verifyEntry_v1_invalidCheckpoint_noSignatures() throws Exception {
    String signedData =
        "rekor.sigstage.dev - 108574341321668964\\n14358\\n7/pPpFdfcoKQFqZOWERBID3lMyEvlHDWOlbRmS5zRl0=\\n\\n";
    String signature =
        "— rekor.sigstage.dev 0y8wozBFAiB8OkuzdwlL6/rDEu2CsIfqmesaH/KLfmIMvlH3YTdIYgIhAPFZeXK6+b0vbWy4GSU/YZxiTpFrrzjsVOShN4LlPdZb\\n";
    String validEnvelope = signedData + signature;
    var entryWithNoSignatures = entryV1.replace(validEnvelope, signedData);
    var rekorEntry = getV1RekorEntry(entryWithNoSignatures);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals("Could not parse checkpoint from envelope", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v1_invalidCheckpoint_excessiveSignatures() throws Exception {
    String signedData =
        "rekor.sigstage.dev - 108574341321668964\\n14358\\n7/pPpFdfcoKQFqZOWERBID3lMyEvlHDWOlbRmS5zRl0=\\n\\n";
    String signature =
        "— rekor.sigstage.dev 0y8wozBFAiB8OkuzdwlL6/rDEu2CsIfqmesaH/KLfmIMvlH3YTdIYgIhAPFZeXK6+b0vbWy4GSU/YZxiTpFrrzjsVOShN4LlPdZb\\n";
    String validEnvelope = signedData + signature;

    var excessiveEnvelopeBuilder = new StringBuilder(signedData);
    // This constant is defined in RekorVerifier.
    final int MAX_CHECKPOINT_SIGNATURES = 20;
    for (int i = 0; i < MAX_CHECKPOINT_SIGNATURES + 1; i++) {
      excessiveEnvelopeBuilder.append(signature);
    }
    String excessiveEnvelope = excessiveEnvelopeBuilder.toString();

    var entryWithExcessiveSignatures = entryV1.replace(validEnvelope, excessiveEnvelope);

    var rekorEntry = getV1RekorEntry(entryWithExcessiveSignatures);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    assertTrue(
        thrown.getMessage().startsWith("Checkpoint contains an excessive number of signatures"));
  }

  @Test
  public void verifyEntry_v1_invalidCheckpoint_treeSizeMismatch() throws Exception {
    var entryWithMismatchedCheckpointTreeSize =
        entryV1.replace(
            "rekor.sigstage.dev - 108574341321668964\\n14358\\n",
            "rekor.sigstage.dev - 108574341321668964\\n14359\\n");
    var rekorEntry = getV1RekorEntry(entryWithMismatchedCheckpointTreeSize);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals(
        "Checkpoint tree size does not match tree size provided in inclusion proof",
        thrown.getMessage());
  }

  @Test
  public void verifyEntry_v2() throws Exception {
    var rekorEntry = getV2RekorEntry(entryV2);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    verifier.verifyEntry(rekorEntry);
  }

  @Test
  public void verifyEntry_v2_invalidLogId() throws Exception {
    var entryMap = GsonSupplier.GSON.get().fromJson(entryV2, Map.class);

    @SuppressWarnings("unchecked")
    Map<String, Object> logIdMap = (Map<String, Object>) entryMap.get("logId");
    logIdMap.put("keyId", "invalid");

    var entryWithInvalidLogId = GsonSupplier.GSON.get().toJson(entryMap);

    var rekorEntry = getV2RekorEntry(entryWithInvalidLogId);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    Assertions.assertEquals(
        "Log entry (logid) does not match any provided transparency logs.", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v2_noInclusionProof() throws Exception {
    var entryMap = GsonSupplier.GSON.get().fromJson(entryV2, Map.class);
    entryMap.remove("inclusionProof");
    var entryWithNoInclusionProof = GsonSupplier.GSON.get().toJson(entryMap);

    var rekorEntry = getV2RekorEntry(entryWithNoInclusionProof);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    Assertions.assertEquals("No inclusion proof in entry.", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v2_invalidCheckpoint_invalidIdentity() throws Exception {
    var entryWithInvalidCheckpoint = entryV2.replace("sigstage", "github");
    var rekorEntry = getV2RekorEntry(entryWithInvalidCheckpoint);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    assertTrue(
        thrown
            .getMessage()
            .startsWith("No matching checkpoint signature found for transparency log"));
  }

  @Test
  public void verifyEntry_v2_invalidCheckpoint_noSignatures() throws Exception {
    String signedData =
        "log2025-alpha1.rekor.sigstage.dev\\n744\\nesdDSd9WE37oIvN7WDlJVKtt/QajruODJO7PVEwwTXs=\\n\\n";
    String signature =
        "— log2025-alpha1.rekor.sigstage.dev 8w1amdUe0s4o19zD+N8ffKDR3+mDCYIBCOX+O8gqThpWp6Rq/07hW+UpMbOdY2i6skEjvY71RebKMx2jt+Hq9JRpJAs=\\n";
    String validEnvelope = signedData + signature;
    var entryWithNoSignatures = entryV2.replace(validEnvelope, signedData);
    var rekorEntry = getV2RekorEntry(entryWithNoSignatures);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    Assertions.assertEquals("Could not parse checkpoint from envelope", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v2_invalidCheckpoint_excessiveSignatures() throws Exception {
    String signedData =
        "log2025-alpha1.rekor.sigstage.dev\\n744\\nesdDSd9WE37oIvN7WDlJVKtt/QajruODJO7PVEwwTXs=\\n\\n";
    String signature =
        "— log2025-alpha1.rekor.sigstage.dev 8w1amdUe0s4o19zD+N8ffKDR3+mDCYIBCOX+O8gqThpWp6Rq/07hW+UpMbOdY2i6skEjvY71RebKMx2jt+Hq9JRpJAs=\\n";
    String validEnvelope = signedData + signature;

    var excessiveEnvelopeBuilder = new StringBuilder(signedData);
    // This constant is defined in RekorVerifier.
    final int MAX_CHECKPOINT_SIGNATURES = 20;
    for (int i = 0; i < MAX_CHECKPOINT_SIGNATURES + 1; i++) {
      excessiveEnvelopeBuilder.append(signature);
    }
    String excessiveEnvelope = excessiveEnvelopeBuilder.toString();

    var entryWithExcessiveSignatures = entryV2.replace(validEnvelope, excessiveEnvelope);

    var rekorEntry = getV2RekorEntry(entryWithExcessiveSignatures);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    assertTrue(
        thrown.getMessage().startsWith("Checkpoint contains an excessive number of signatures"));
  }

  @Test
  public void verifyEntry_v2_invalidCheckpoint_invalidSignature() throws Exception {
    var entryWithInvalidCheckpoint = entryV2.replace("+Hq9J", "+Hq9K");
    var rekorEntry = getV2RekorEntry(entryWithInvalidCheckpoint);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(rekorEntry);
            });
    Assertions.assertEquals("Checkpoint signature was invalid", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v2_invalidCheckpoint_treeSizeMismatch() throws Exception {
    var entryWithMismatchedCheckpointTreeSize =
        entryV2.replace(
            "log2025-alpha1.rekor.sigstage.dev\\n744\\n",
            "log2025-alpha1.rekor.sigstage.dev\\n745\\n");
    var rekorEntry = getV2RekorEntry(entryWithMismatchedCheckpointTreeSize);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals(
        "Checkpoint tree size does not match tree size provided in inclusion proof",
        thrown.getMessage());
  }

  @Test
  public void verifyEntry_v1_nonHexLogId() throws Exception {
    var entryWithNonHexLogId =
        entryV1.replace(
            "\"logID\": \"d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496\"",
            "\"logID\": \"not_hex_string!\"");
    var rekorEntry = getV1RekorEntry(entryWithNonHexLogId);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals("Log entry (logid) is not a valid hex string.", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v1_invalidBase64Set() throws Exception {
    var rekorEntry = getV1RekorEntry(entryV1);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var verification =
        ImmutableVerification.builder()
            .from(rekorEntry.getVerification())
            .signedEntryTimestamp("not_base64!")
            .build();
    var entryWithInvalidSet =
        ImmutableRekorEntry.builder().from(rekorEntry).verification(verification).build();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(entryWithInvalidSet));
    Assertions.assertEquals("Entry SET is not valid base64", thrown.getMessage());
    Assertions.assertInstanceOf(IllegalArgumentException.class, thrown.getCause());
  }

  @Test
  public void verifyEntry_v1_invalidInclusionProof_hashesNotHex() throws Exception {
    var invalidHashesEntry =
        entryV1.replace(
            "\"810320ec3029914695826d60133c67021f66ee0cfb09a6f79eb267ed9f55de2c\"",
            "\"not_hex_hash!\"");
    var rekorEntry = getV1RekorEntry(invalidHashesEntry);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals("Inclusion proof contains invalid hex strings", thrown.getMessage());
  }

  @Test
  public void verifyEntry_v1_invalidCheckpoint_rootHashNotBase64() throws Exception {
    String signedData =
        "rekor.sigstage.dev - 108574341321668964\\n14358\\n7/pPpFdfcoKQFqZOWERBID3lMyEvlHDWOlbRmS5zRl0=\\n\\n";
    String invalidSignedData =
        "rekor.sigstage.dev - 108574341321668964\\n14358\\nnot_base64!\\n\\n";
    var entryWithInvalidCheckpointRoot = entryV1.replace(signedData, invalidSignedData);
    var rekorEntry = getV1RekorEntry(entryWithInvalidCheckpointRoot);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(rekorEntry));
    Assertions.assertEquals("Checkpoint root hash is not valid base64", thrown.getMessage());
  }

  private RekorEntry getV2RekorEntry(String json)
      throws InvalidProtocolBufferException, RekorParseException {
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(json, transparencyLogEntryBuilder);
    return ProtoMutators.toRekorEntry(transparencyLogEntryBuilder.build());
  }

  private RekorEntry getV1RekorEntry(String json) throws Exception {
    return dev.sigstore.rekor.client.RekorResponse.newRekorResponse(
            new java.net.URI("https://not.used"), json)
        .getEntry();
  }
}
