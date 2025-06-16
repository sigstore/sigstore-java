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

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import dev.sigstore.json.GsonSupplier;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RekorV2VerifierTest {
  public static SigstoreTrustedRoot trustRoot;
  public static String entry;
  public static RekorV2Verifier verifier;

  @BeforeEach
  public void loadResources() throws IOException {
    entry =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/entry-rekor-v2.json"),
            StandardCharsets.UTF_8);
  }

  @BeforeAll
  public static void initTrustRoot() throws Exception {
    trustRoot =
        SigstoreTrustedRoot.from(
            Resources.getResource("dev/sigstore/trustroot/staging_trusted_root.json").openStream());
  }

  @Test
  public void verifyEntry() throws Exception {
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entry, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();
    verifier.verifyEntry(transparencyLogEntry, timestamp);
  }

  @Test
  public void verifyEntry_invalidLogId() throws Exception {
    var entryMap = GsonSupplier.GSON.get().fromJson(entry, Map.class);

    @SuppressWarnings("unchecked")
    Map<String, Object> logIdMap = (Map<String, Object>) entryMap.get("logId");
    logIdMap.put("keyId", "invalid");

    var entryWithInvalidLogId = GsonSupplier.GSON.get().toJson(entryMap);

    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithInvalidLogId, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    Assertions.assertEquals(
        "Log entry (logid, timestamp) does not match any provided transparency logs.",
        thrown.getMessage());
  }

  @Test
  public void verifyEntry_withNoInclusionProof() throws Exception {
    var entryMap = GsonSupplier.GSON.get().fromJson(entry, Map.class);
    entryMap.remove("inclusionProof");
    var entryWithNoInclusionProof = GsonSupplier.GSON.get().toJson(entryMap);

    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithNoInclusionProof, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    Assertions.assertEquals("Inclusion proof verification failed", thrown.getMessage());
  }

  @Test
  public void verifyEntry_invalidCheckpoint_invalidIdentity() throws Exception {
    var entryWithInvalidCheckpoint = entry.replace("sigstage", "github");
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithInvalidCheckpoint, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    assertTrue(
        thrown
            .getMessage()
            .startsWith("No matching checkpoint signature found for transparency log"));
  }

  @Test
  public void verifyEntry_invalidCheckpoint_noSignatures() throws Exception {
    String signedData =
        "log2025-alpha1.rekor.sigstage.dev\\n744\\nesdDSd9WE37oIvN7WDlJVKtt/QajruODJO7PVEwwTXs=\\n\\n";
    String signature =
        "— log2025-alpha1.rekor.sigstage.dev 8w1amdUe0s4o19zD+N8ffKDR3+mDCYIBCOX+O8gqThpWp6Rq/07hW+UpMbOdY2i6skEjvY71RebKMx2jt+Hq9JRpJAs=\\n";
    String validEnvelope = signedData + signature;
    var entryWithNoSignatures = entry.replace(validEnvelope, signedData);
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithNoSignatures, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    Assertions.assertEquals("Could not parse checkpoint from envelope", thrown.getMessage());
  }

  @Test
  public void verifyEntry_invalidCheckpoint_excessiveSignatures() throws Exception {
    String signedData =
        "log2025-alpha1.rekor.sigstage.dev\\n744\\nesdDSd9WE37oIvN7WDlJVKtt/QajruODJO7PVEwwTXs=\\n\\n";
    String signature =
        "— log2025-alpha1.rekor.sigstage.dev 8w1amdUe0s4o19zD+N8ffKDR3+mDCYIBCOX+O8gqThpWp6Rq/07hW+UpMbOdY2i6skEjvY71RebKMx2jt+Hq9JRpJAs=\\n";
    String validEnvelope = signedData + signature;

    StringBuilder excessiveEnvelopeBuilder = new StringBuilder(signedData);
    // This constant is defined in {@Link RekorV2Verifier}.
    final int MAX_CHECKPOINT_SIGNATURES = 20;
    for (int i = 0; i < MAX_CHECKPOINT_SIGNATURES + 1; i++) {
      excessiveEnvelopeBuilder.append(signature);
    }
    String excessiveEnvelope = excessiveEnvelopeBuilder.toString();

    var entryWithExcessiveSignatures = entry.replace(validEnvelope, excessiveEnvelope);

    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithExcessiveSignatures, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    assertTrue(
        thrown.getMessage().startsWith("Checkpoint contains an excessive number of signatures"));
  }

  @Test
  public void verifyEntry_invalidCheckpoint_invalidSignature() throws Exception {
    var entryWithInvalidCheckpoint = entry.replace("+Hq9J", "+Hq9K");
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entryWithInvalidCheckpoint, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2025, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    Assertions.assertEquals("Checkpoint signature was invalid", thrown.getMessage());
  }

  @Test
  public void verifyEntry_invalidTimestamp() throws Exception {
    var transparencyLogEntryBuilder = TransparencyLogEntry.newBuilder();
    ProtoJson.parser().merge(entry, transparencyLogEntryBuilder);
    var transparencyLogEntry = transparencyLogEntryBuilder.build();
    verifier = RekorV2Verifier.newRekorV2Verifier(trustRoot);

    var timestamp = OffsetDateTime.of(2024, 6, 12, 12, 24, 0, 0, ZoneOffset.UTC).toInstant();

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class,
            () -> {
              verifier.verifyEntry(transparencyLogEntry, timestamp);
            });
    Assertions.assertEquals(
        "Log entry (logid, timestamp) does not match any provided transparency logs.",
        thrown.getMessage());
  }
}
