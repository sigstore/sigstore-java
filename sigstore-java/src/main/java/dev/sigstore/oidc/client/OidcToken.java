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

import org.immutables.value.Value;

/** A token from a provider with both openid and email scope claims. */
@Value.Immutable
public interface OidcToken {
  /** The subject or email claim from the token to include in the SAN on the certificate. */
  String getSubjectAlternativeName();

  /** The issuer of the id token. */
  String getIssuer();

  /** The full oidc token obtained from the provider. */
  @Value.Redacted
  String getIdToken();
}
