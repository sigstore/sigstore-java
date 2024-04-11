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

import java.util.Map;

public interface OidcClient {

  /**
   * Determine if this client can be used in the current environment. For example, we can ignore
   * Oidc Clients that are scoped to a specific CI environment
   *
   * @param env the configured system environment
   * @return true if we should use credentials from this client
   */
  boolean isEnabled(Map<String, String> env);

  OidcToken getIDToken(Map<String, String> env) throws OidcException;
}
