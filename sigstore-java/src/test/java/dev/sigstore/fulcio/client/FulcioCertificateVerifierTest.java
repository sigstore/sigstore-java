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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;
import dev.sigstore.KeylessVerificationRequest.CertificateIdentity;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.testing.CertGenerator;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FulcioCertificateVerifierTest {

  private static X509Certificate certificate;
  private static FulcioCertificateVerifier verifier;

  @BeforeAll
  public static void createCertificate() throws Exception {
    certificate = (X509Certificate) CertGenerator.newCert(Signers.newEcdsaSigner().getPublicKey());
    verifier = new FulcioCertificateVerifier();
  }

  @Test
  public void verifyCertificateMatches_requiredOids() throws Exception {
    verifier.verifyCertificateMatches(
        certificate,
        ImmutableList.of(
            CertificateIdentity.builder()
                .subjectAlternativeName("test@test.com")
                .issuer("https://fakeaccounts.test.com")
                .build()));
  }

  @Test
  public void verifyCertificateMatches_withOther() throws Exception {
    verifier.verifyCertificateMatches(
        certificate,
        ImmutableList.of(
            CertificateIdentity.builder()
                .subjectAlternativeName("test@test.com")
                .issuer("https://fakeaccounts.test.com")
                .other(ImmutableMap.of("1.3.6.1.4.1.99999.42.42", "test value"))
                .build()));
  }

  @Test
  public void verifyCertificateMatches_anyOf() throws Exception {
    verifier.verifyCertificateMatches(
        certificate,
        ImmutableList.of(
            CertificateIdentity.builder()
                .subjectAlternativeName("not-match")
                .issuer("not-match")
                .build(),
            CertificateIdentity.builder()
                .subjectAlternativeName("test@test.com")
                .issuer("https://fakeaccounts.test.com")
                .build()));
  }

  @Test
  public void verifyCertificateMatches_noMatch() {
    Assertions.assertThrows(
        FulcioVerificationException.class,
        () ->
            verifier.verifyCertificateMatches(
                certificate,
                ImmutableList.of(
                    CertificateIdentity.builder()
                        .subjectAlternativeName("not-match")
                        .issuer("not-match")
                        .build())));
  }

  @Test
  public void verifyCertificateMatches_noMatchButMostlyMatch() {
    Assertions.assertThrows(
        FulcioVerificationException.class,
        () ->
            verifier.verifyCertificateMatches(
                certificate,
                ImmutableList.of(
                    CertificateIdentity.builder()
                        .subjectAlternativeName("test@test.com")
                        .issuer("https://fakeaccounts.test.com")
                        .other(ImmutableMap.of("1.3.6.1.4.1.99999.42.42", "not-match"))
                        .build())));
  }

  @Test
  public void verifyCertificateMatches_fromCachedEmailCert() throws Exception {
    var certificate =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toString(
                    Resources.getResource("dev/sigstore/samples/certs/cert-single.pem"),
                    StandardCharsets.UTF_8));
    verifier.verifyCertificateMatches(
        certificate,
        ImmutableList.of(
            CertificateIdentity.builder()
                .subjectAlternativeName("appu@google.com")
                .issuer("https://accounts.google.com")
                .build()));
  }

  @Test
  public void verifyCertificateMatches_fromCachedGithubOidcCert() throws Exception {
    var certificate =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toString(
                    Resources.getResource("dev/sigstore/samples/certs/cert-githuboidc.pem"),
                    StandardCharsets.UTF_8));
    verifier.verifyCertificateMatches(
        certificate,
        ImmutableList.of(
            CertificateIdentity.builder()
                .subjectAlternativeName(
                    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.4.0")
                .issuer("https://token.actions.githubusercontent.com")
                .other(
                    ImmutableMap.of(
                        "1.3.6.1.4.1.57264.1.1",
                        "https://token.actions.githubusercontent.com",
                        "1.3.6.1.4.1.57264.1.2",
                        "workflow_dispatch",
                        "1.3.6.1.4.1.57264.1.3",
                        "4ffe2674e1e9e268c00a4f4afa5264fdd399d453",
                        "1.3.6.1.4.1.57264.1.4",
                        "Tag and Build Release",
                        "1.3.6.1.4.1.57264.1.5",
                        "sigstore/sigstore-java",
                        "1.3.6.1.4.1.57264.1.6",
                        "refs/heads/main"))
                .build()));
  }
}
