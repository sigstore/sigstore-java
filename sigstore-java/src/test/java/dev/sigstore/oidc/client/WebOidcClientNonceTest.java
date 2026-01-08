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
package dev.sigstore.oidc.client;

import com.gargoylesoftware.htmlunit.WebClient;
import com.google.common.io.Resources;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WebOidcClientNonceTest {

  private MockOAuth2Server server;

  @AfterEach
  void teardown() throws IOException {
    if (server != null) {
      server.shutdown();
    }
  }

  @Test
  void testNonceVerificationSuccess() throws Exception {
    String config =
        Resources.toString(
            Resources.getResource("dev/sigstore/oidc/server/config.json"), StandardCharsets.UTF_8);
    server = new MockOAuth2Server(OAuth2Config.Companion.fromJson(config));
    server.start();

    try (var webClient = new WebClient()) {
      var oidcClient =
          WebOidcClient.builder()
              .setIssuer(Service.of(server.issuerUrl("test-default").uri(), 1))
              .setBrowser(webClient::getPage)
              .build();

      var token = oidcClient.getIDToken(Map.of());
      Assertions.assertNotNull(token.getIdToken());
    }
  }

  @Test
  void testNonceVerificationFailure_MismatchedNonce() throws Exception {
    String config =
        Resources.toString(
            Resources.getResource("dev/sigstore/oidc/server/config-bad-nonce.json"),
            StandardCharsets.UTF_8);
    server = new MockOAuth2Server(OAuth2Config.Companion.fromJson(config));
    server.start();

    try (var webClient = new WebClient()) {
      var oidcClient =
          WebOidcClient.builder()
              .setIssuer(Service.of(server.issuerUrl("test-default").uri(), 1))
              .setBrowser(webClient::getPage)
              .build();

      OidcException exception =
          Assertions.assertThrows(
              OidcException.class,
              () -> {
                oidcClient.getIDToken(Map.of());
              });
      Assertions.assertTrue(exception.getMessage().contains("nonce in id token does not match"));
    }
  }
}
