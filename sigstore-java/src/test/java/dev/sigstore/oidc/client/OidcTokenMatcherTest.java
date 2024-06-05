/*
 * Copyright 2024 The Sigstore Authors.
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

import dev.sigstore.strings.RegexSyntaxException;
import dev.sigstore.strings.StringMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OidcTokenMatcherTest {

  @Test
  public void testString() {
    var testMatcher =
        OidcTokenMatcher.of(StringMatcher.string("test-san"), StringMatcher.string("test-issuer"));
    Assertions.assertTrue(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertTrue(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("wrong-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("wrong-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("")
                .issuer("")
                .build()));

    Assertions.assertEquals(
        "{subjectAlternativeName: 'String: test-san', issuer: 'String: test-issuer'}",
        testMatcher.toString());
  }

  @Test
  public void testRegex() throws RegexSyntaxException {
    var testMatcher =
        OidcTokenMatcher.of(StringMatcher.regex("test-..."), StringMatcher.regex("test-.*"));
    Assertions.assertTrue(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertTrue(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("wrong-san")
                .issuer("test-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("test-san")
                .issuer("wrong-issuer")
                .build()));
    Assertions.assertFalse(
        testMatcher.test(
            ImmutableOidcToken.builder()
                .idToken("hidden stuff")
                .subjectAlternativeName("")
                .issuer("")
                .build()));

    Assertions.assertEquals(
        "{subjectAlternativeName: 'RegEx: test-...', issuer: 'RegEx: test-.*'}",
        testMatcher.toString());
  }
}
