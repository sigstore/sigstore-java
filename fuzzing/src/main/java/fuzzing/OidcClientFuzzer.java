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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.gargoylesoftware.htmlunit.WebClient;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import dev.sigstore.oidc.client.OidcClient;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.WebOidcClient;
import java.io.IOException;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;

public class OidcClientFuzzer {
  private static MockOAuth2Server server;
  private static String issuer;

  public static void fuzzerInitialize() {
    // Prepare MockOAuth2Server
    try {
      var oauthServerConfig =
          Resources.toString(Resources.getResource("oidc-config.json"), Charsets.UTF_8);
      var cfg = OAuth2Config.Companion.fromJson(oauthServerConfig);
      server = new MockOAuth2Server(cfg);
      server.start();
      issuer = server.issuerUrl("test-default").toString();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    if (server != null) {
      server.shutdown();
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try (var webClient = new WebClient()) {
      boolean choice1 = data.consumeBoolean();
      boolean choice2 = data.consumeBoolean();
      String string = data.consumeRemainingAsAsciiString();

      OidcClient oidcClient = null;

      if (choice1) {
        oidcClient =
            WebOidcClient.builder().setIssuer(issuer).setBrowser(webClient::getPage).build();
      } else {
        oidcClient = GithubActionsOidcClient.builder().audience(string).build();
      }

      if (choice2) {
        OidcClients.of(oidcClient).getIDToken();
      } else {
        oidcClient.getIDToken();
      }
    } catch (OidcException | IllegalArgumentException e) {
      // Known exception
    }
  }
}

