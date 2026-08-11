/*
 * Copyright 2026 The Sigstore Authors.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.common.io.Resources;
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.testing.CertGenerator;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorClientHttpMockTest {

  private static HashedRekordRequest req;
  private static String entryJson;

  @BeforeAll
  public static void setup() throws Exception {
    req = createdRekorRequest();
    entryJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/entry.json"),
            StandardCharsets.UTF_8);
  }

  @Test
  public void putEntry_success201() throws Exception {
    try (var server = new MockWebServer()) {
      server.enqueue(
          new MockResponse()
              .setResponseCode(201)
              .setHeader(
                  "Location",
                  "/api/v1/log/entries/ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af")
              .setBody(entryJson));
      server.start();

      var client =
          RekorClientHttp.builder().setService(Service.of(server.url("/").uri(), 1)).build();
      var resp = client.putEntry(req);

      assertNotNull(resp);
      assertEquals(
          "ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af", resp.getUuid());

      var recordedRequest = server.takeRequest();
      assertEquals("POST", recordedRequest.getMethod());
      assertEquals("/api/v1/log/entries", recordedRequest.getPath());
    }
  }

  @Test
  public void putEntry_conflict409_handled() throws Exception {
    try (var server = new MockWebServer()) {
      // 1. POST returns 409 Conflict with Location header
      server.enqueue(
          new MockResponse()
              .setResponseCode(409)
              .setHeader(
                  "Location",
                  "/api/v1/log/entries/ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af")
              .setBody("{\"code\":409,\"message\":\"conflict\"}"));

      // 2. GET to Location returns 200 OK with entry
      server.enqueue(new MockResponse().setResponseCode(200).setBody(entryJson));

      server.start();

      var client =
          RekorClientHttp.builder().setService(Service.of(server.url("/").uri(), 1)).build();
      var resp = client.putEntry(req);

      assertNotNull(resp);
      assertEquals(
          "ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af", resp.getUuid());

      // Verify POST request
      var postRequest = server.takeRequest();
      assertEquals("POST", postRequest.getMethod());
      assertEquals("/api/v1/log/entries", postRequest.getPath());

      // Verify GET request to Location
      var getRequest = server.takeRequest();
      assertEquals("GET", getRequest.getMethod());
      assertEquals(
          "/api/v1/log/entries/ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af",
          getRequest.getPath());
    }
  }

  @Test
  public void putEntry_otherError500_propagates() throws Exception {
    try (var server = new MockWebServer()) {
      server.enqueue(new MockResponse().setResponseCode(500).setBody("internal server error"));
      server.start();

      var client =
          RekorClientHttp.builder().setService(Service.of(server.url("/").uri(), 1)).build();

      assertThrows(IOException.class, () -> client.putEntry(req));
    }
  }

  private static HashedRekordRequest createdRekorRequest() throws Exception {
    var data = "some data " + UUID.randomUUID();
    var artifactDigest =
        MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);
    var signature = signer.sign(data.getBytes(StandardCharsets.UTF_8));
    var cert = Certificates.toPemBytes(CertGenerator.newCert(signer.getPublicKey()));
    return HashedRekordRequest.newHashedRekordRequest(artifactDigest, cert, signature);
  }
}
