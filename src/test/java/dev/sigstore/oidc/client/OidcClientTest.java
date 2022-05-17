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
package dev.sigstore.oidc.client;

import com.gargoylesoftware.htmlunit.WebClient;
import dev.sigstore.testing.MockOAuth2ServerExtension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class OidcClientTest {

  @RegisterExtension
  private static final MockOAuth2ServerExtension server = new MockOAuth2ServerExtension();

  @Test
  public void testAuthFlow() throws OidcException {
    try (var webClient = new WebClient()) {
      var oidcClient =
          OidcClient.builder().setIssuer(server.getIssuer()).setBrowser(webClient::getPage).build();

      var eid = oidcClient.getIDToken(null);
      Assertions.assertEquals(
          MockOAuth2ServerExtension.DEFAULT_CONFIGURED_EMAIL, eid.getEmailAddress());
    }
  }
}
