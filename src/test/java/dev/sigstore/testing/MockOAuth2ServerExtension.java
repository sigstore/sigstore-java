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
package dev.sigstore.testing;

import com.gargoylesoftware.htmlunit.WebClient;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import dev.sigstore.oidc.client.OidcClient;
import dev.sigstore.oidc.client.OidcException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/** Junit5 extension that starts and stops an oauth server. Use with @RegisterExtension. */
public class MockOAuth2ServerExtension implements BeforeAllCallback, AfterAllCallback {
  public static final String DEFAULT_CONFIGURED_EMAIL = "test.person@test.com";

  private static final String OAUTH_ISSUER_ID = "test-default";
  private MockOAuth2Server mockOAuthServer;
  private String issuer;
  private Path fulcioConfig;

  @Override
  public void beforeAll(ExtensionContext context) throws Exception {
    try {
      var oauthServerConfig =
          Resources.toString(
              Resources.getResource("dev/sigstore/oidc/server/config.json"), Charsets.UTF_8);
      var cfg = OAuth2Config.Companion.fromJson(oauthServerConfig);
      mockOAuthServer = new MockOAuth2Server(cfg);
      mockOAuthServer.start();

      issuer = mockOAuthServer.issuerUrl(OAUTH_ISSUER_ID).toString();
      fulcioConfig = Files.createTempFile("fulcio-config", ".json");
      Files.writeString(
          fulcioConfig,
          String.format(
              "{\"OIDCIssuers\":{ \"%s\": { \"IssuerURL\": \"%s\", \"ClientID\": \"sigstore\", \"Type\": \"email\"}}}",
              issuer, issuer));
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }

  @Override
  public void afterAll(ExtensionContext context) throws Exception {
    mockOAuthServer.shutdown();
    Files.deleteIfExists(fulcioConfig);
  }

  public OidcClient.EmailIdToken getOidcToken() throws OidcException {
    // obtain oauth token
    try (var webClient = new WebClient()) {
      var oidcClient =
          OidcClient.builder()
              .setIssuer(mockOAuthServer.issuerUrl(OAUTH_ISSUER_ID).toString())
              .setBrowser(webClient::getPage)
              .build();

      return oidcClient.getIDToken(null);
    }
  }

  public String getIssuer() {
    return issuer;
  }

  public Path getFulcioConfig() {
    return fulcioConfig;
  }
}
