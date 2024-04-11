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
import io.github.netmikey.logunit.api.LogCapturer;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.event.Level;

public class WebOidcClientTest {

  @RegisterExtension
  private static final MockOAuth2ServerExtension server = new MockOAuth2ServerExtension();

  @RegisterExtension
  LogCapturer logs = LogCapturer.create().captureForType(WebOidcClient.class, Level.DEBUG);

  @Test
  public void testAuthFlow() throws OidcException {
    try (var webClient = new WebClient()) {
      var oidcClient =
          WebOidcClient.builder()
              .setIssuer(server.getIssuer())
              .setBrowser(webClient::getPage)
              .build();

      var eid = oidcClient.getIDToken(System.getenv());
      Assertions.assertEquals(
          MockOAuth2ServerExtension.DEFAULT_CONFIGURED_EMAIL, eid.getSubjectAlternativeName());
    }
  }

  @Test
  public void isEnabled_CI() {
    var client = WebOidcClient.builder().build();
    Assertions.assertFalse(client.isEnabled(Map.of("CI", "true")));
    logs.assertContains("Skipping browser based oidc provider because CI detected");
  }

  @Test
  public void isEnabled_notCI() {
    var client = WebOidcClient.builder().build();
    Assertions.assertTrue(client.isEnabled(Map.of("CI", "false")));
  }
}
