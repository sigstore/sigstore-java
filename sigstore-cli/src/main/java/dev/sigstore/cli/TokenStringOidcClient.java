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
package dev.sigstore.cli;

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import dev.sigstore.oidc.client.ImmutableOidcToken;
import dev.sigstore.oidc.client.OidcClient;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.OidcToken;
import java.io.IOException;

public class TokenStringOidcClient implements OidcClient {

  private final String idToken;

  public TokenStringOidcClient(String idToken) {
    this.idToken = idToken;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public OidcToken getIDToken() throws OidcException {
    try {
      var jws = JsonWebSignature.parse(new GsonFactory(), idToken);
      return ImmutableOidcToken.builder()
          .idToken(idToken)
          .subjectAlternativeName(jws.getPayload().getSubject())
          .build();
    } catch (IOException e) {
      throw new OidcException("Failed to parse JWT", e);
    }
  }
}
