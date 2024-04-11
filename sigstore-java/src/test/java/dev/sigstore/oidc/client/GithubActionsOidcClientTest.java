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

import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import io.github.netmikey.logunit.api.LogCapturer;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.event.Level;

public class GithubActionsOidcClientTest {

  @RegisterExtension
  LogCapturer logs =
      LogCapturer.create().captureForType(GithubActionsOidcClient.class, Level.DEBUG);

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  public void getToken() throws OidcException {
    var client = GithubActionsOidcClient.builder().build();
    var token = client.getIDToken(System.getenv());

    Assertions.assertNotNull(token.getSubjectAlternativeName());
    Assertions.assertNotNull(token.getIdToken());
  }

  @Test
  public void isEnabled_github() {
    var client = GithubActionsOidcClient.builder().build();
    var env =
        Map.of(
            GithubActionsOidcClient.GITHUB_ACTIONS_KEY,
            "ignored",
            GithubActionsOidcClient.REQUEST_TOKEN_KEY,
            "ignored",
            GithubActionsOidcClient.REQUEST_URL_KEY,
            "ignored");
    Assertions.assertTrue(client.isEnabled(env));
  }

  @Test
  public void isEnabled_githubButNoTokenInfo() {
    var client = GithubActionsOidcClient.builder().build();
    var env = Map.of(GithubActionsOidcClient.GITHUB_ACTIONS_KEY, "ignored");
    Assertions.assertFalse(client.isEnabled(env));
    logs.assertContains(
        "Github env detected, but github idtoken not found: skipping github actions oidc");
  }

  @Test
  public void isEnabled_notGithub() {
    var client = GithubActionsOidcClient.builder().build();
    Assertions.assertFalse(client.isEnabled(Map.of()));
    logs.assertContains("Github env not detected: skipping github actions oidc");
  }
}
