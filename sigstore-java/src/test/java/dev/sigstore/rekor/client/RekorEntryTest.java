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
package dev.sigstore.rekor.client;

import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.common.v1.LogId;
import dev.sigstore.proto.rekor.v1.Checkpoint;
import dev.sigstore.proto.rekor.v1.InclusionPromise;
import dev.sigstore.proto.rekor.v1.InclusionProof;
import dev.sigstore.proto.rekor.v1.KindVersion;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RekorEntryTest {

  private static final String MOCK_BODY_JSON =
      "{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{}}";
  private static final ByteString MOCK_BODY_BYTESTRING = ByteString.copyFromUtf8(MOCK_BODY_JSON);
  private static final String MOCK_BODY_B64 =
      Base64.getEncoder().encodeToString(MOCK_BODY_JSON.getBytes(StandardCharsets.UTF_8));

  @Test
  public void fromTLogEntry_full() throws Exception {
    var tle =
        TransparencyLogEntry.newBuilder()
            .setLogIndex(123)
            .setLogId(LogId.newBuilder().setKeyId(ByteString.fromHex("abcdef")))
            .setIntegratedTime(456)
            .setKindVersion(KindVersion.newBuilder().setKind("hashedrekord").setVersion("0.0.1"))
            .setCanonicalizedBody(MOCK_BODY_BYTESTRING)
            .setInclusionPromise(
                InclusionPromise.newBuilder()
                    .setSignedEntryTimestamp(ByteString.copyFromUtf8("set")))
            .setInclusionProof(
                InclusionProof.newBuilder()
                    .setLogIndex(123)
                    .setTreeSize(789)
                    .setRootHash(ByteString.fromHex("fedcba"))
                    .setCheckpoint(Checkpoint.newBuilder().setEnvelope("checkpoint envelope"))
                    .addHashes(ByteString.fromHex("01"))
                    .addHashes(ByteString.fromHex("02")))
            .build();

    var entry = ProtoMutators.toRekorEntry(tle);

    Assertions.assertEquals(123, entry.getLogIndex());
    Assertions.assertEquals("abcdef", entry.getLogID());
    Assertions.assertEquals(456, entry.getIntegratedTime());
    Assertions.assertEquals(MOCK_BODY_B64, entry.getBody());

    var verification = entry.getVerification();
    Assertions.assertNotNull(verification);
    Assertions.assertEquals(
        Base64.getEncoder().encodeToString("set".getBytes(StandardCharsets.UTF_8)),
        verification.getSignedEntryTimestamp());

    var inclusionProof = verification.getInclusionProof();
    Assertions.assertNotNull(inclusionProof);
    Assertions.assertEquals(123, inclusionProof.getLogIndex());
    Assertions.assertEquals(789, inclusionProof.getTreeSize());
    Assertions.assertEquals("fedcba", inclusionProof.getRootHash());
    Assertions.assertEquals("checkpoint envelope", inclusionProof.getCheckpoint());
    Assertions.assertEquals(List.of("01", "02"), inclusionProof.getHashes());
  }

  @Test
  public void fromTLogEntry_minimal() throws Exception {
    // TLE with no inclusion promise or proof
    var tle =
        TransparencyLogEntry.newBuilder()
            .setLogIndex(123)
            .setLogId(LogId.newBuilder().setKeyId(ByteString.fromHex("abcdef")))
            .setIntegratedTime(456)
            .setKindVersion(KindVersion.newBuilder().setKind("hashedrekord").setVersion("0.0.1"))
            .setCanonicalizedBody(MOCK_BODY_BYTESTRING)
            .build();

    var entry = ProtoMutators.toRekorEntry(tle);
    Assertions.assertEquals(123, entry.getLogIndex());
    Assertions.assertEquals("abcdef", entry.getLogID());
    Assertions.assertEquals(456, entry.getIntegratedTime());
    Assertions.assertEquals(MOCK_BODY_B64, entry.getBody());

    var verification = entry.getVerification();
    Assertions.assertNotNull(verification);
    Assertions.assertNull(verification.getSignedEntryTimestamp());
    Assertions.assertNull(verification.getInclusionProof());
  }

  @Test
  public void fromTLogEntryJson() throws Exception {
    var tle =
        TransparencyLogEntry.newBuilder()
            .setLogIndex(123)
            .setLogId(LogId.newBuilder().setKeyId(ByteString.fromHex("abcdef")))
            .setIntegratedTime(456)
            .setKindVersion(KindVersion.newBuilder().setKind("hashedrekord").setVersion("0.0.1"))
            .setCanonicalizedBody(MOCK_BODY_BYTESTRING)
            .build();

    var json = JsonFormat.printer().print(tle);
    var entry = RekorEntry.fromTLogEntryJson(json);

    Assertions.assertEquals(123, entry.getLogIndex());
    Assertions.assertEquals("abcdef", entry.getLogID());
  }

  @Test
  public void fromTLogEntryJson_invalid() {
    var thrown =
        Assertions.assertThrows(
            RekorParseException.class, () -> RekorEntry.fromTLogEntryJson("{invalid"));
    Assertions.assertTrue(thrown.getMessage().startsWith("Failed to parse Rekor response JSON"));
  }

  @Test
  public void getSignableContent() throws Exception {
    var entry =
        ImmutableRekorEntry.builder()
            .body(MOCK_BODY_B64)
            .integratedTime(456)
            .logID("abcdef")
            .logIndex(123)
            .verification(ImmutableVerification.builder().build())
            .build();

    String expectedJson =
        "{\"body\":\""
            + entry.getBody()
            + "\",\"integratedTime\":456,\"logID\":\"abcdef\",\"logIndex\":123}";
    byte[] expectedCanonical = new JsonCanonicalizer(expectedJson).getEncodedUTF8();

    Assertions.assertArrayEquals(expectedCanonical, entry.getSignableContent());
  }

  @Test
  public void getBodyDecoded() throws Exception {
    var entry =
        ImmutableRekorEntry.builder()
            .body(MOCK_BODY_B64)
            .integratedTime(456)
            .logID("abcdef")
            .logIndex(123)
            .verification(ImmutableVerification.builder().build())
            .build();

    var bodyDecoded = entry.getBodyDecoded();
    Assertions.assertEquals("0.0.1", bodyDecoded.getApiVersion());
    Assertions.assertEquals("hashedrekord", bodyDecoded.getKind());
    Assertions.assertNotNull(bodyDecoded.getSpec());
  }
}
