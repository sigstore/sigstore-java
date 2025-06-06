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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.sigstore.trustroot.LegacySigningConfig;
import dev.sigstore.trustroot.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import okio.Buffer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TimestampClientHttpTest {
  private static TimestampRequest tsReq;

  private static final byte[] INVALID_TS_RESP_BYTES = new byte[14];

  @BeforeAll
  public static void setup() throws Exception {
    var digest = MessageDigest.getInstance("SHA-256");
    var artifactHashBytes = digest.digest("test".getBytes(StandardCharsets.UTF_8));
    tsReq =
        ImmutableTimestampRequest.builder()
            .hash(artifactHashBytes)
            .hashAlgorithm(HashAlgorithm.SHA256)
            .build();
  }

  @Test
  public void timestamp_success() throws Exception {
    var client =
        TimestampClientHttp.builder()
            .setService(LegacySigningConfig.STAGING.getTsas().get(0))
            .build();

    var tsResp = client.timestamp(tsReq);

    assertNotNull(tsResp);
    assertNotNull(tsResp.getEncoded());
    assertTrue(tsResp.getEncoded().length > 0);

    var bcTsResp = new org.bouncycastle.tsp.TimeStampResponse(tsResp.getEncoded());
    var tsToken = bcTsResp.getTimeStampToken();
    assertNotNull(tsToken);

    var tsInfo = tsToken.getTimeStampInfo();
    assertNotNull(tsInfo);

    assertArrayEquals(tsReq.getHash(), tsInfo.getMessageImprintDigest());

    assertEquals(tsReq.getNonce(), tsInfo.getNonce());

    var expectedOid = tsReq.getHashAlgorithm().getOid();
    assertEquals(expectedOid, tsInfo.getMessageImprintAlgOID());
  }

  @Test
  public void timestamp_failure_badResponse_incorrectDigestLength() throws Exception {
    var tsReqWithIncorrectDigestLength =
        ImmutableTimestampRequest.builder()
            .hash(tsReq.getHash())
            .hashAlgorithm(HashAlgorithm.SHA512)
            .nonce(tsReq.getNonce())
            .build();

    var client =
        TimestampClientHttp.builder()
            .setService(LegacySigningConfig.STAGING.getTsas().get(0))
            .build();

    var tse =
        assertThrows(
            TimestampException.class,
            () -> {
              client.timestamp(tsReqWithIncorrectDigestLength);
            });
    assertEquals(
        "Timestamp request failed: bad response from timestamp @ 'https://timestamp.sigstage.dev/api/v1/timestamp' : {\"code\":400,\"message\":\"Message digest has incorrect length for specified algorithm\"}",
        tse.getMessage());
  }

  @Test
  public void timestamp_failure_badResponse_nonRetryableError() throws Exception {
    try (var server = new MockWebServer()) {
      server.enqueue(new MockResponse().setResponseCode(418));
      server.start();

      var tsaUri = server.url("/v1/timestamp/").uri();
      var client = TimestampClientHttp.builder().setService(Service.of(tsaUri, 1)).build();

      var tse =
          assertThrows(
              TimestampException.class,
              () -> {
                client.timestamp(tsReq);
              });
      assertTrue(
          tse.getMessage().startsWith("Timestamp request failed: bad response from timestamp"));
    }
  }

  @Test
  public void timestamp_failure_badResponse_RetryableError() throws Exception {
    try (var server = new MockWebServer()) {
      for (var i = 0; i < 6; i++) {
        server.enqueue(new MockResponse().setResponseCode(500));
      }
      server.start();

      var tsaUri = server.url("/v1/timestamp/").uri();
      var client = TimestampClientHttp.builder().setService(Service.of(tsaUri, 1)).build();

      var tse =
          assertThrows(
              TimestampException.class,
              () -> {
                client.timestamp(tsReq);
              });
      assertTrue(
          tse.getMessage().startsWith("Timestamp request failed: bad response from timestamp"));
    }
  }

  @Test
  public void timestamp_failure_invalidResponseFormat() throws Exception {
    try (var server = new MockWebServer()) {
      var buffer = new Buffer();
      buffer.write(INVALID_TS_RESP_BYTES);
      server.enqueue(new MockResponse().setBody(buffer));
      server.start();

      var tsaUri = server.url("/v1/timestamp/").uri();
      var client = TimestampClientHttp.builder().setService(Service.of(tsaUri, 1)).build();

      var tse =
          assertThrows(
              TimestampException.class,
              () -> {
                client.timestamp(tsReq);
              });
      assertEquals(
          "Timestamp response validation or parsing failed: unexpected end-of-contents marker",
          tse.getMessage());
    }
  }

  @Test
  public void timestamp_failure_responseBodyReadError() throws Exception {
    try (var server = new MockWebServer()) {
      server.enqueue(
          new MockResponse()
              .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY)
              .setChunkedBody("some initial data", 1)); // Send a bit then disconnect
      server.start();

      var tsaUri = server.url("/v1/timestamp/").uri();
      var client = TimestampClientHttp.builder().setService(Service.of(tsaUri, 1)).build();

      var tse =
          assertThrows(
              TimestampException.class,
              () -> {
                client.timestamp(tsReq);
              });
      assertEquals(
          "Timestamp response validation or parsing failed: unknown tag 0 encountered",
          tse.getMessage());
    }
  }
}
