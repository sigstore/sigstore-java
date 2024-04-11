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
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.OidcToken;
import dev.sigstore.oidc.client.WebOidcClient;
import java.io.IOException;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import org.junit.jupiter.api.extension.*;

/**
 * Junit5 extension that starts and stops an oauth server. Will write a per test storage item
 * MOCK_OAUTH_ISSUER, for fulcio to use during initialization.
 */
public class MockOAuth2ServerExtension
    implements BeforeEachCallback, AfterEachCallback, ParameterResolver {
  public static final String DEFAULT_CONFIGURED_EMAIL = "test.person@test.com";

  private static final String OAUTH_ISSUER_ID = "test-default";
  private MockOAuth2Server mockOAuthServer;
  private String issuer;

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    try {
      var oauthServerConfig =
          Resources.toString(
              Resources.getResource("dev/sigstore/oidc/server/config.json"), Charsets.UTF_8);
      var cfg = OAuth2Config.Companion.fromJson(oauthServerConfig);
      mockOAuthServer = new MockOAuth2Server(cfg);
      mockOAuthServer.start();

      issuer = mockOAuthServer.issuerUrl(OAUTH_ISSUER_ID).toString();
      var ns = ExtensionContext.Namespace.create(context.getTestMethod().orElseThrow().toString());
      context.getStore(ns).put("MOCK_OAUTH_ISSUER", issuer);
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    mockOAuthServer.shutdown();
  }

  public OidcToken getOidcToken() throws OidcException {
    // obtain oauth token
    try (var webClient = new WebClient()) {
      var oidcClient =
          WebOidcClient.builder()
              .setIssuer(mockOAuthServer.issuerUrl(OAUTH_ISSUER_ID).toString())
              .setBrowser(webClient::getPage)
              .build();

      return oidcClient.getIDToken(System.getenv());
    }
  }

  public String getIssuer() {
    return issuer;
  }

  @Override
  public boolean supportsParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return (parameterContext.getParameter().getType() == MockOAuth2ServerExtension.class);
  }

  @Override
  public Object resolveParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return this;
  }
}
