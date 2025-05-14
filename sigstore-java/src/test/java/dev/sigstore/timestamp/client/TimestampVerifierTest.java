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
package dev.sigstore.timestamp.client;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.common.io.Resources;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TimestampVerifierTest {
  private static SigstoreTrustedRoot trustedRoot;
  private static SigstoreTrustedRoot trustedRootWithOutdatedTsa;
  private static SigstoreTrustedRoot trustedRootWithMultipleTsas;
  private static byte[] trustedTsRespBytesWithEmbeddedCerts;
  private static byte[] trustedTsRespBytesWithoutEmbeddedCerts;
  private static byte[] invalidTsRespBytes;
  private static byte[] untrustedTsRespBytes;

  @BeforeAll
  public static void loadResources() throws Exception {
    // Response from Sigstore TSA (in trusted root) with embedded certs
    try (var is =
        Resources.getResource(
                "dev/sigstore/samples/timestamp-response/valid/sigstore_tsa_response_with_embedded_certs.tsr")
            .openStream()) {
      trustedTsRespBytesWithEmbeddedCerts = is.readAllBytes();
    }

    // Response from Sigstore TSA (in trusted root) without embedded certs
    try (var is =
        Resources.getResource(
                "dev/sigstore/samples/timestamp-response/valid/sigstore_tsa_response_without_embedded_certs.tsr")
            .openStream()) {
      if (is == null) {
        throw new IOException(
            "dev/sigstore/samples/timestamp-response/valid/sigstore_tsa_response_without_embedded_certs.tsr");
      }
      trustedTsRespBytesWithoutEmbeddedCerts = is.readAllBytes();
    }

    // Response from FreeTSA (not in trusted root)
    try (var is =
        Resources.getResource("dev/sigstore/samples/timestamp-response/valid/freetsa_response.tsr")
            .openStream()) {
      if (is == null) {
        throw new IOException("dev/sigstore/samples/timestamp-response/valid/freetsa_response.tsr");
      }
      untrustedTsRespBytes = is.readAllBytes();
    }

    // Invalid response (binary content modified) from Sigstore TSA
    try (var is =
        Resources.getResource(
                "dev/sigstore/samples/timestamp-response/invalid/sigstore_tsa_response_invalid.tsr")
            .openStream()) {
      if (is == null) {
        throw new IOException(
            "dev/sigstore/samples/timestamp-response/invalid/sigstore_tsa_response_invalid.tsr");
      }
      invalidTsRespBytes = is.readAllBytes();
    }
  }

  @BeforeAll
  public static void initTrustRoot() throws Exception {
    var json =
        Resources.toString(
            Resources.getResource("dev/sigstore/trustroot/trusted_root.json"),
            StandardCharsets.UTF_8);
    var builder = TrustedRoot.newBuilder();
    JsonFormat.parser().merge(json, builder);

    trustedRoot = SigstoreTrustedRoot.from(builder.build());

    json =
        Resources.toString(
            Resources.getResource("dev/sigstore/trustroot/trusted_root_with_outdated_tsa.json"),
            StandardCharsets.UTF_8);
    builder = TrustedRoot.newBuilder();
    JsonFormat.parser().merge(json, builder);

    trustedRootWithOutdatedTsa = SigstoreTrustedRoot.from(builder.build());

    json =
        Resources.toString(
            Resources.getResource("dev/sigstore/trustroot/trusted_root_with_multiple_tsas.json"),
            StandardCharsets.UTF_8);
    builder = TrustedRoot.newBuilder();
    JsonFormat.parser().merge(json, builder);

    trustedRootWithMultipleTsas = SigstoreTrustedRoot.from(builder.build());
  }

  @Test
  public void verify_success_validResponseWithEmbeddedCerts() throws Exception {
    var tsResp =
        ImmutableTimestampResponse.builder().encoded(trustedTsRespBytesWithEmbeddedCerts).build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRoot);

    assertDoesNotThrow(() -> verifier.verify(tsResp));
  }

  @Test
  public void verify_success_validResponseWithoutEmbeddedCerts() throws Exception {
    var tsResp =
        ImmutableTimestampResponse.builder()
            .encoded(trustedTsRespBytesWithoutEmbeddedCerts)
            .build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRoot);

    assertDoesNotThrow(() -> verifier.verify(tsResp));
  }

  @Test
  public void verify_success_validResponseWithEmbeddedCerts_multipleTsas() throws Exception {
    var tsResp =
        ImmutableTimestampResponse.builder().encoded(trustedTsRespBytesWithEmbeddedCerts).build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRootWithMultipleTsas);

    assertDoesNotThrow(() -> verifier.verify(tsResp));
  }

  @Test
  public void verify_success_validResponseWithoutEmbeddedCerts_multipleTsas() throws Exception {
    var tsResp =
        ImmutableTimestampResponse.builder()
            .encoded(trustedTsRespBytesWithoutEmbeddedCerts)
            .build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRootWithMultipleTsas);

    assertDoesNotThrow(() -> verifier.verify(tsResp));
  }

  @Test
  public void verify_failure_invalidResponse() throws Exception {
    var tsResp = ImmutableTimestampResponse.builder().encoded(invalidTsRespBytes).build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRoot);

    var tsve = assertThrows(TimestampVerificationException.class, () -> verifier.verify(tsResp));
    assertEquals("Failed to parse TimeStampResponse", tsve.getMessage());
  }

  @Test
  public void verify_failure_untrustedTsa() throws Exception {
    var tsResp = ImmutableTimestampResponse.builder().encoded(untrustedTsRespBytes).build();
    assertNotNull(tsResp.getEncoded());

    var verifier = TimestampVerifier.newTimestampVerifier(trustedRoot);

    var tsve = assertThrows(TimestampVerificationException.class, () -> verifier.verify(tsResp));
    assertEquals(
        "Certificates in token were not verifiable against TSAs\nhttps://timestamp.sigstore.dev (Embedded leaf certificate does not match this trusted TSA's leaf.)",
        tsve.getMessage());
  }

  @Test
  public void verify_failure_outdatedTsa() throws Exception {
    var tsResp =
        ImmutableTimestampResponse.builder().encoded(trustedTsRespBytesWithEmbeddedCerts).build();
    assertNotNull(tsResp.getEncoded());

    var verifier = TimestampVerifier.newTimestampVerifier(trustedRootWithOutdatedTsa);

    var tsve = assertThrows(TimestampVerificationException.class, () -> verifier.verify(tsResp));
    assertEquals(
        "Certificate was not verifiable against TSAs\nhttps://timestamp.sigstore.dev (Timestamp generation time is not within TSA's validity period.)",
        tsve.getMessage());
  }

  @Test
  public void verify_failure_tsLacksToken() throws Exception {
    var tsRespGen = new TimeStampResponseGenerator(null, null);
    var bcFailTsResp =
        tsRespGen.generateFailResponse(
            PKIStatus.rejection.getValue().intValue(),
            PKIFailureInfo.badAlg,
            "Simulated TSA rejection - no token");
    var failResponseBytes = bcFailTsResp.getEncoded();

    var tsResp = ImmutableTimestampResponse.builder().encoded(failResponseBytes).build();
    var verifier = TimestampVerifier.newTimestampVerifier(trustedRoot);

    var tsve = assertThrows(TimestampVerificationException.class, () -> verifier.verify(tsResp));
    assertEquals("No TimeStampToken found in response", tsve.getMessage());
  }
}
