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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class GithubActionsOidcClientTest {

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  public void getToken() throws OidcException {
    var client = GithubActionsOidcClient.builder().build();
    var token = client.getIDToken();

    Assertions.assertNotNull(token.getSubjectAlternativeName());
    Assertions.assertNotNull(token.getIdToken());
  }
}
