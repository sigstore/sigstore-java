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

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import java.io.IOException;
import java.util.Map;

/**
 * This should only be used when the user has an out of band mechanism for obtaining an OIDC token
 * to be consumed by a sigstore signing event. So it should not be included in any defaults for
 * {@link OidcClients}.
 *
 * <p>It's not explicitly designed for multi use, but implementers of the {@link
 * TokenStringProvider} may include mechanisms for longer lived signing events. Each time a token is
 * requested, the provider may execute a fetch of the token.
 */
public class TokenStringOidcClient implements OidcClient {

  private final TokenStringProvider idTokenProvider;

  TokenStringOidcClient(TokenStringProvider provider) {
    this.idTokenProvider = provider;
  }

  public static TokenStringOidcClient from(TokenStringProvider provider) {
    return new TokenStringOidcClient(provider);
  }

  public static TokenStringOidcClient from(String token) {
    return new TokenStringOidcClient(() -> token);
  }

  @Override
  public boolean isEnabled(Map<String, String> env) {
    return true;
  }

  @Override
  public OidcToken getIDToken(Map<String, String> env) throws OidcException {
    try {
      var idToken = idTokenProvider.getTokenString();
      var jws = JsonWebSignature.parse(new GsonFactory(), idToken);
      return ImmutableOidcToken.builder()
          .idToken(idToken)
          .issuer(jws.getPayload().getIssuer())
          .subjectAlternativeName(jws.getPayload().getSubject())
          .build();
    } catch (IOException e) {
      throw new OidcException("Failed to parse JWT", e);
    } catch (Exception e) {
      throw new OidcException("Failed to obtain token", e);
    }
  }

  @FunctionalInterface
  public interface TokenStringProvider {
    String getTokenString() throws Exception;
  }
}
