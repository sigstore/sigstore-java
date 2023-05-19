/*
 * Copyright 2023 The Sigstore Authors.
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
package fuzzing;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import dev.sigstore.encryption.signers.Signer;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.fulcio.client.CertificateRequest;
import dev.sigstore.fulcio.client.FulcioClient;
import dev.sigstore.fulcio.client.UnsupportedAlgorithmException;
import dev.sigstore.http.ImmutableHttpParams;
import io.grpc.StatusRuntimeException;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jetbrains.annotations.NotNull;

public class FulcioClientFuzzer {
  private static MockOAuth2Server mockOAuthServer;
  private static MockWebServer mockCTLogServer;

  public static void fuzzerInitialize() {
    try {
      // Prepare MockOAuth2Server
      var oauthServerConfig =
          Resources.toString(Resources.getResource("oidc-config.json"), Charsets.UTF_8);
      var cfg = OAuth2Config.Companion.fromJson(oauthServerConfig);
      mockOAuthServer = new MockOAuth2Server(cfg);

      // Prepare MockWebServer for CTLog
      mockCTLogServer = new MockWebServer();
      mockCTLogServer.setDispatcher(
          new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest recordedRequest)
                throws InterruptedException {
              var path = recordedRequest.getPath();
              if ("/ct/v1/add-chain".equals(path) || "/ct/v1/add-pre-chain".equals(path)) {
                return handleSctRequest();
              }
              return new MockResponse().setResponseCode(404);
            }
          });

      // Start mock server
      mockOAuthServer.start();
      mockCTLogServer.start();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    try {
      if (mockOAuthServer != null) {
        mockOAuthServer.shutdown();
      }
      if (mockCTLogServer != null) {
        mockCTLogServer.shutdown();
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  // This fuzzer start a mock oauth2 server and a mock CTLog web server
  // when the fuzzing is started. For each fuzzing iteration it creates
  // a FulcioClient, then it create and sign a certificate request generated
  // randomly for each fuzzing iteration. The mock server will then reply with
  // a signing response.
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      URI uri = URI.create("localhost:5554");
      Signer signer = Signers.newEcdsaSigner();

      byte[] byteArray = data.consumeRemainingAsBytes();
      String string = new String(byteArray, Charset.defaultCharset());

      // Create fulcio client
      FulcioClient client =
          FulcioClient.builder()
              .setHttpParams(ImmutableHttpParams.builder().allowInsecureConnections(true).build())
              .setServerUrl(uri)
              .build();

      // Fuzz certificate signing request
      CertificateRequest request =
          CertificateRequest.newCertificateRequest(
              signer.getPublicKey(), string, signer.sign(byteArray));

      client.signingCertificate(request);
    } catch (IllegalArgumentException
        | InterruptedException
        | InvalidKeyException
        | SignatureException
        | CertificateException
        | UnsupportedAlgorithmException
        | NoSuchAlgorithmException
        | StatusRuntimeException
        | IOException e) {
      // Known exception
    }
  }

  private static MockResponse handleSctRequest() {
    Map<String, Object> content = new HashMap<>();
    content.put("sct_version", 0);

    // Create mock response for CTLog
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      content.put("id", digest.digest("test_id".getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    // Add data to the mock response
    content.put(
        "signature",
        Base64.getDecoder()
            .decode(
                "BAMARjBEAiBwHMgDtObhrT8wkWid01FXlqvXz1tsRei64siSuwZp7gIgdyRBYHatNaOezI/AW57lKkUffra4cKOGdO+oHKBJARI="));
    content.put("timestamp", System.currentTimeMillis());
    String resp = GSON.get().toJson(content);

    return new MockResponse().setResponseCode(200).setBody(resp);
  }
}
