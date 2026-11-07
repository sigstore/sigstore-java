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
package dev.sigstore.fulcio.client;

import com.google.common.io.Resources;
import dev.sigstore.ImmutableCTLogOptions;
import dev.sigstore.VerificationOptions.CTLogOptions;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.trustroot.CertificateAuthority;
import dev.sigstore.trustroot.ImmutableCertificateAuthority;
import dev.sigstore.trustroot.ImmutableLogId;
import dev.sigstore.trustroot.ImmutableSubject;
import dev.sigstore.trustroot.ImmutableTransparencyLog;
import dev.sigstore.trustroot.ImmutableValidFor;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FulcioVerifierTest {
  private static String certs;
  private static String certsWithEmbeddedSct;
  private static String bundleFile;

  private static SigstoreTrustedRoot trustRoot;

  @BeforeAll
  public static void loadResources() throws IOException {
    certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/cert.pem"),
            StandardCharsets.UTF_8);

    certsWithEmbeddedSct =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
            StandardCharsets.UTF_8);

    bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.sigstore"),
            StandardCharsets.UTF_8);
  }

  @BeforeAll
  public static void initTrustRoot() throws Exception {
    trustRoot =
        SigstoreTrustedRoot.from(
            Resources.getResource("dev/sigstore/trustroot/trusted_root.json").openStream());
  }

  @Test
  public void testVerifySct_nullCtLogKey() throws Exception {
    var signingCertificate = Certificates.fromPemChain(certsWithEmbeddedSct);
    var fulcioVerifier =
        FulcioVerifier.newFulcioVerifier(trustRoot.getCAs(), Collections.emptyList());
    try {
      fulcioVerifier.verifySigningCertificate(signingCertificate);
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals("No ct logs were provided to verifier", fve.getMessage());
    }
  }

  @Test
  public void testVerifySct_noSct() throws Exception {
    var signingCertificate = Certificates.fromPemChain(certs);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    try {
      fulcioVerifier.verifySct(signingCertificate, enabledCTLog());
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals("No valid SCTs were found during verification", fve.getMessage());
    }
  }

  @Test
  public void validSigningCertAndEmbeddedSct() throws Exception {
    var signingCertificate = Certificates.fromPemChain(certsWithEmbeddedSct);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    fulcioVerifier.verifySigningCertificate(signingCertificate);
  }

  @Test
  public void validBundle() throws Exception {
    var bundle = Bundle.from(new StringReader(bundleFile));
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    Assertions.assertEquals(1, bundle.getCertPath().getCertificates().size());
    fulcioVerifier.verifySigningCertificate(bundle.getCertPath());
  }

  @Test
  public void invalidEmbeddedSct() throws Exception {
    var signingCertificate = Certificates.fromPemChain(certsWithEmbeddedSct);
    var fulcioVerifier =
        FulcioVerifier.newFulcioVerifier(
            trustRoot.getCAs(),
            List.of(
                ImmutableTransparencyLog.builder()
                    .from(trustRoot.getCTLogs().get(0))
                    .logId(
                        ImmutableLogId.builder()
                            .keyId("abcd".getBytes(StandardCharsets.UTF_8))
                            .build())
                    .build()));

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () -> fulcioVerifier.verifySct(signingCertificate, enabledCTLog()));
    Assertions.assertEquals("No valid SCTs were found, all(1) SCTs were invalid", fve.getMessage());
  }

  @Test
  public void codeSigningLeafFromPrivateCa() throws Exception {
    var ca = new TestCa();
    var leaf =
        ca.issueLeaf(
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning));
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.ca), List.of());

    fulcioVerifier.verifySigningCertificate(
        Certificates.toCertPath(leaf), CTLogOptions.builder().isEnabled(false).build());
  }

  @Test
  public void leafWithoutCodeSigningEku() throws Exception {
    var ca = new TestCa();
    var leaf =
        ca.issueLeaf(
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.ca), List.of());

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () ->
                fulcioVerifier.verifySigningCertificate(
                    Certificates.toCertPath(leaf),
                    CTLogOptions.builder().isEnabled(false).build()));
    Assertions.assertEquals(
        "Signing certificate extended key usage does not include codeSigning", fve.getMessage());
  }

  @Test
  public void leafWithoutDigitalSignatureKeyUsage() throws Exception {
    var ca = new TestCa();
    var leaf =
        ca.issueLeaf(
            new KeyUsage(KeyUsage.keyEncipherment),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning));
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.ca), List.of());

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () ->
                fulcioVerifier.verifySigningCertificate(
                    Certificates.toCertPath(leaf),
                    CTLogOptions.builder().isEnabled(false).build()));
    Assertions.assertEquals(
        "Signing certificate key usage does not include digitalSignature", fve.getMessage());
  }

  private static @NonNull ImmutableCTLogOptions enabledCTLog() {
    return CTLogOptions.builder().isEnabled(true).build();
  }

  /** A self-signed CA, standing in for a private deployment's fulcio CA. */
  private static class TestCa {
    private final X500Name name = new X500Name("CN=test-ca,O=test");
    private final KeyPair keyPair;
    private final CertificateAuthority ca;
    private final Instant now = Instant.now();

    TestCa() throws Exception {
      keyPair = newKeyPair();
      var root =
          new JcaX509v3CertificateBuilder(
                  name,
                  BigInteger.ONE,
                  Date.from(now.minus(Duration.ofHours(1))),
                  Date.from(now.plus(Duration.ofHours(1))),
                  name,
                  keyPair.getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
              .addExtension(
                  Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      ca =
          ImmutableCertificateAuthority.builder()
              .certPath(Certificates.toCertPath(sign(root)))
              .uri(URI.create("https://fulcio.test"))
              .validFor(ImmutableValidFor.builder().start(now.minus(Duration.ofHours(1))).build())
              .subject(ImmutableSubject.builder().organization("test").commonName("test").build())
              .build();
    }

    X509Certificate issueLeaf(KeyUsage keyUsage, ExtendedKeyUsage extendedKeyUsage)
        throws Exception {
      var leaf =
          new JcaX509v3CertificateBuilder(
                  name,
                  BigInteger.TWO,
                  Date.from(now.minus(Duration.ofMinutes(1))),
                  Date.from(now.plus(Duration.ofMinutes(10))),
                  new X500Name("O=sigstore.dev"),
                  newKeyPair().getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
              .addExtension(Extension.keyUsage, true, keyUsage)
              .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)
              .addExtension(
                  Extension.subjectAlternativeName,
                  true,
                  new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.com")));
      return sign(leaf);
    }

    private X509Certificate sign(X509v3CertificateBuilder builder) throws Exception {
      var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
      return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static KeyPair newKeyPair() throws Exception {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      return keyPairGenerator.generateKeyPair();
    }
  }
}
