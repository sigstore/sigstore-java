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
package dev.sigstore.oidc.client;

import com.google.common.collect.ImmutableList;
import java.util.Map;
import java.util.logging.Logger;

/** An ordered list of oidc clients to use when looking for credentials. */
public class OidcClients {

  private static final Logger log = Logger.getLogger(OidcClients.class.getName());

  public static final OidcClients PUBLIC_GOOD =
      of(GithubActionsOidcClient.builder().build(), WebOidcClient.builder().build());

  public static final OidcClients STAGING =
      of(
          GithubActionsOidcClient.builder().build(),
          WebOidcClient.builder().setIssuer(WebOidcClient.STAGING_DEX_ISSUER).build());

  private final ImmutableList<OidcClient> clients;
  private final Map<String, String> env;

  public static OidcClients of(OidcClient... clients) {
    return new OidcClients(ImmutableList.copyOf(clients), System.getenv());
  }

  private OidcClients(ImmutableList<OidcClient> clients, Map<String, String> env) {
    this.clients = clients;
    this.env = env;
  }

  /**
   * Attempts to obtain a token from the first enabled oidc provider and errors if a failure occurs,
   * does not try other providers if the first provider fails.
   *
   * @return an oidc token
   * @throws OidcException if token request fails or if no valid provider was found
   */
  public OidcToken getIDToken() throws OidcException {
    for (var client : clients) {
      if (client.isEnabled(env)) {
        return client.getIDToken(env);
      }
    }
    log.info(
        "Could not find an oidc provider, if you are in CI make sure the token is available to the sigstore signing process");
    throw new OidcException("Could not find an oidc provider");
  }
}
