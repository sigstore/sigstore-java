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
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import dev.sigstore.oidc.client.OidcClient;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcException;

public class GithubActionsOidcClientFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      boolean choice = data.consumeBoolean();
      String string = data.consumeRemainingAsAsciiString();

      OidcClient oidcClient = GithubActionsOidcClient.builder().audience(string).build();

      if (choice) {
        OidcClients.of(oidcClient).getIDToken();
      } else {
        oidcClient.getIDToken();
      }
    } catch (OidcException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
