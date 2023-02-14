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

/** An ordered list of oidc clients to use when looking for credentials. */
public class OidcClients {

  public static final OidcClients DEFAULTS =
      of(GithubActionsOidcClient.builder().build(), WebOidcClient.builder().build());

  public static final OidcClients STAGING_DEFAULTS =
      of(
          GithubActionsOidcClient.builder().build(),
          WebOidcClient.builder().setIssuer(WebOidcClient.STAGING_DEX_ISSUER).build());

  private final ImmutableList<OidcClient> clients;

  public static OidcClients of(OidcClient... clients) {
    return new OidcClients(ImmutableList.copyOf(clients));
  }

  private OidcClients(ImmutableList<OidcClient> clients) {
    this.clients = clients;
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
      if (client.isEnabled()) {
        return client.getIDToken();
      }
    }
    throw new OidcException("Could not find an oidc provider");
  }
}
