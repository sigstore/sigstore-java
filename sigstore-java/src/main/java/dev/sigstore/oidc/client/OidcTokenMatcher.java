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

import dev.sigstore.strings.StringMatcher;
import java.util.function.Predicate;

/**
 * An interface for allowing direct string matching or regular expressions on {@link OidcToken}. Use
 * the static factory {@link #of(StringMatcher, StringMatcher)} to instantiate the matcher. Custom
 * implementations should override {@link Object#toString} for better error reporting.
 */
public interface OidcTokenMatcher extends Predicate<OidcToken> {

  static OidcTokenMatcher of(StringMatcher san, StringMatcher issuer) {
    return new OidcTokenMatcher() {
      @Override
      public boolean test(OidcToken oidcToken) {
        return san.test(oidcToken.getSubjectAlternativeName())
            && issuer.test(oidcToken.getIssuer());
      }

      @Override
      public String toString() {
        return "{subjectAlternativeName: " + san + ", issuer: " + issuer + "}";
      }
    };
  }
}
