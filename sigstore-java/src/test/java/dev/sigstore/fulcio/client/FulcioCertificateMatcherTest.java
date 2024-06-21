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
package dev.sigstore.fulcio.client;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;
import dev.sigstore.VerificationOptions.UncheckedCertificateException;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.testing.CertGenerator;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FulcioCertificateMatcherTest {

  private static X509Certificate certificate;

  @BeforeAll
  public static void createCertificate() throws Exception {
    certificate = (X509Certificate) CertGenerator.newCert(Signers.newEcdsaSigner().getPublicKey());
  }

  @Test
  public void test_requiredOids() {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("test@test.com"))
            .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
            .build();
    Assertions.assertTrue(matcher.test(certificate));
  }

  @Test
  public void test_withOther() throws Exception {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("test@test.com"))
            .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
            .oidRawStrings(
                ImmutableMap.of("1.3.6.1.4.1.99999.42.42", StringMatcher.string("test value")))
            .oidDerAsn1Strings(
                ImmutableMap.of("1.3.6.1.4.1.99999.42.43", StringMatcher.string("test value der")))
            .oidBytes(
                ImmutableMap.of(
                    "1.3.6.1.4.1.99999.42.42",
                    new DEROctetString("test value".getBytes(StandardCharsets.UTF_8)).getEncoded()))
            .build();
    Assertions.assertTrue(matcher.test(certificate));
  }

  @Test
  public void test_noMatch() {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("not-match"))
            .issuer(StringMatcher.string("not-match"))
            .build();
    Assertions.assertFalse(matcher.test(certificate));
  }

  @Test
  public void test_wantRawButActualIsDer() {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("test@test.com"))
            .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
            .oidRawStrings(
                ImmutableMap.of("1.3.6.1.4.1.99999.42.43", StringMatcher.string("test value der")))
            .build();
    Assertions.assertFalse(matcher.test(certificate));
  }

  @Test
  public void test_wantDerButActualIsRaw() {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("test@test.com"))
            .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
            .oidDerAsn1Strings(
                ImmutableMap.of("1.3.6.1.4.1.99999.42.42", StringMatcher.string("test value")))
            .build();
    Assertions.assertThrows(UncheckedCertificateException.class, () -> matcher.test(certificate));
  }

  @Test
  public void test_bytesDoNotMatch() {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("test@test.com"))
            .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
            .oidBytes(
                ImmutableMap.of(
                    "1.3.6.1.4.1.99999.42.42", "test value".getBytes(StandardCharsets.UTF_8)))
            .build();
    Assertions.assertFalse(matcher.test(certificate));
  }

  @Test
  public void test_fromCachedEmailCert() throws Exception {
    var certificate =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toString(
                    Resources.getResource("dev/sigstore/samples/certs/cert-single.pem"),
                    StandardCharsets.UTF_8));
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.string("appu@google.com"))
            .issuer(StringMatcher.string("https://accounts.google.com"))
            .build();
    Assertions.assertTrue(matcher.test(certificate));
  }

  @Test
  public void test_fromCachedGithubOidcCert() throws Exception {
    var certificate =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toString(
                    Resources.getResource("dev/sigstore/samples/certs/cert-githuboidc.pem"),
                    StandardCharsets.UTF_8));
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(
                StringMatcher.string(
                    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.4.0"))
            .issuer(StringMatcher.string("https://token.actions.githubusercontent.com"))
            .oidRawStrings(
                ImmutableMap.of(
                    "1.3.6.1.4.1.57264.1.1",
                    StringMatcher.string("https://token.actions.githubusercontent.com"),
                    "1.3.6.1.4.1.57264.1.2",
                    StringMatcher.string("workflow_dispatch"),
                    "1.3.6.1.4.1.57264.1.3",
                    StringMatcher.string("4ffe2674e1e9e268c00a4f4afa5264fdd399d453"),
                    "1.3.6.1.4.1.57264.1.4",
                    StringMatcher.string("Tag and Build Release"),
                    "1.3.6.1.4.1.57264.1.5",
                    StringMatcher.string("sigstore/sigstore-java"),
                    "1.3.6.1.4.1.57264.1.6",
                    StringMatcher.string("refs/heads/main")))
            .build();
    Assertions.assertTrue(matcher.test(certificate));
  }

  @Test
  public void test_fromCachedGithubOidcCertWithRegEx() throws Exception {
    var certificate =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toString(
                    Resources.getResource("dev/sigstore/samples/certs/cert-githuboidc.pem"),
                    StandardCharsets.UTF_8));
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(
                StringMatcher.regex(
                    "https://github\\.com/slsa-framework/slsa-github-generator/\\.github/workflows/generator_generic_slsa3.yml@refs/tags/v\\d+\\.\\d+\\.\\d+"))
            .issuer(StringMatcher.string("https://token.actions.githubusercontent.com"))
            .build();
    Assertions.assertTrue(matcher.test(certificate));
  }

  @Test
  public void testToString() throws Exception {
    var matcher =
        ImmutableFulcioCertificateMatcher.builder()
            .subjectAlternativeName(StringMatcher.regex("https://github\\.com/.*"))
            .issuer(StringMatcher.string("https://token.actions.githubusercontent.com"))
            .oidRawStrings(Map.of("1.2.3", StringMatcher.string("test-rawString")))
            .oidDerAsn1Strings(Map.of("1.2.3", StringMatcher.string("test-rawString")))
            .oidBytes(Map.of("1.2.3", "test-rawString".getBytes(StandardCharsets.UTF_8)))
            .build();
    Assertions.assertEquals(
        "{issuer:'String: https://token.actions.githubusercontent.com',san:'RegEx: https://github\\.com/.*',oidRawStrings:{1.2.3:'String: test-rawString'},oidDerAsn1Strings:{1.2.3:'String: test-rawString'},oidBytes:{1.2.3:'hex: 746573742d726177537472696e67'}}",
        matcher.toString());
  }
}
