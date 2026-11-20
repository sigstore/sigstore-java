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
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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

  @ParameterizedTest(name = "{0}")
  @MethodSource("validLeafProfiles")
  public void validLeafProfile(String caseName, LeafFactory leafFactory) throws Exception {
    var ca = new TestCa();
    var leaf = leafFactory.create(ca);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.authority), List.of());

    fulcioVerifier.verifySigningCertificate(Certificates.toCertPath(leaf), disabledCTLog());
  }

  static Stream<Arguments> validLeafProfiles() {
    return Stream.of(
        valid("standard code-signing leaf", ca -> ca.leaf().build()),
        valid(
            "leaf without BasicConstraints",
            ca -> ca.leaf().without(Extension.basicConstraints).build()));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("invalidLeafProfiles")
  public void invalidLeafProfile(String caseName, LeafFactory leafFactory, String expectedMessage)
      throws Exception {
    var ca = new TestCa();
    var leaf = leafFactory.create(ca);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.authority), List.of());

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () ->
                fulcioVerifier.verifySigningCertificate(
                    Certificates.toCertPath(leaf), disabledCTLog()));
    Assertions.assertEquals(expectedMessage, fve.getMessage());
  }

  static Stream<Arguments> invalidLeafProfiles() {
    return Stream.of(
        invalid(
            "X.509 v1 certificate",
            TestCa::issueV1Leaf,
            "Signing certificate must be X.509 v3, but was v1"),
        invalid(
            "non-critical BasicConstraints",
            ca -> ca.leaf().bc(false, false).build(),
            "Signing certificate BasicConstraints extension must be marked critical"),
        invalid(
            "malformed non-critical BasicConstraints",
            ca -> ca.leaf().ext(Extension.basicConstraints, false, new byte[] {1, 2, 3}).build(),
            "Signing certificate BasicConstraints extension must be marked critical"),
        invalid(
            "CA certificate in leaf position",
            ca -> ca.leaf().bc(true, true).build(),
            "Signing certificate must not be a CA"),
        invalid(
            "missing KeyUsage",
            ca -> ca.leaf().without(Extension.keyUsage).build(),
            "Signing certificate is missing KeyUsage extension"),
        invalid(
            "non-critical KeyUsage",
            ca -> ca.leaf().ku(false, KeyUsage.digitalSignature).build(),
            "Signing certificate KeyUsage extension must be marked critical"),
        invalid(
            "KeyUsage includes extra usages",
            ca -> ca.leaf().ku(KeyUsage.digitalSignature | KeyUsage.keyCertSign).build(),
            "Signing certificate key usage must only include digitalSignature"),
        invalid(
            "KeyUsage missing digitalSignature",
            ca -> ca.leaf().ku(KeyUsage.keyEncipherment).build(),
            "Signing certificate key usage does not include digitalSignature"),
        invalid(
            "missing ExtendedKeyUsage",
            ca -> ca.leaf().without(Extension.extendedKeyUsage).build(),
            "Signing certificate is missing ExtendedKeyUsage extension"),
        invalid(
            "critical ExtendedKeyUsage",
            ca -> ca.leaf().eku(true, KeyPurposeId.id_kp_codeSigning).build(),
            "Signing certificate ExtendedKeyUsage extension must not be marked critical"),
        invalid(
            "malformed non-critical ExtendedKeyUsage",
            ca -> ca.leaf().ext(Extension.extendedKeyUsage, false, new byte[] {1, 2, 3}).build(),
            "Could not parse signing certificate ExtendedKeyUsage extension"),
        invalid(
            "ExtendedKeyUsage without codeSigning (serverAuth)",
            ca -> ca.leaf().eku(false, KeyPurposeId.id_kp_serverAuth).build(),
            "Signing certificate extended key usage does not include codeSigning"),
        invalid(
            "ExtendedKeyUsage with anyExtendedKeyUsage only",
            ca -> ca.leaf().eku(false, KeyPurposeId.anyExtendedKeyUsage).build(),
            "Signing certificate extended key usage does not include codeSigning"),
        invalid(
            "ExtendedKeyUsage with multiple EKUs including codeSigning",
            ca ->
                ca.leaf()
                    .eku(false, KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_codeSigning)
                    .build(),
            "Signing certificate extended key usage must only include codeSigning"));
  }

  private static Arguments valid(String name, LeafFactory leaf) {
    return Arguments.of(name, leaf);
  }

  private static Arguments invalid(String name, LeafFactory leaf, String expectedMessage) {
    return Arguments.of(name, leaf, expectedMessage);
  }

  @Test
  public void intermediateCertificateEkuChecks() throws Exception {
    var ca = new TestCa();
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(List.of(ca.authority), List.of());

    // Intermediate with codeSigning EKU passes.
    var validWithEku =
        ca.issueChainWithIntermediate(
            new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).getEncoded());
    fulcioVerifier.verifySigningCertificate(validWithEku, disabledCTLog());

    // Intermediate without EKU (unconstrained) passes.
    var validWithoutEku = ca.issueChainWithIntermediate(null);
    fulcioVerifier.verifySigningCertificate(validWithoutEku, disabledCTLog());

    // Intermediate with non-codeSigning EKU is rejected.
    var invalidIntermediate =
        ca.issueChainWithIntermediate(
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded());
    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () -> fulcioVerifier.verifySigningCertificate(invalidIntermediate, disabledCTLog()));
    Assertions.assertEquals(
        "Intermediate certificate extended key usage does not include codeSigning",
        fve.getMessage());

    // Intermediate with malformed non-critical EKU is rejected (including on JDK <= 17).
    var malformedIntermediate = ca.issueChainWithIntermediate(new byte[] {1, 2, 3});
    var malformedFve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () -> fulcioVerifier.verifySigningCertificate(malformedIntermediate, disabledCTLog()));
    Assertions.assertEquals(
        "Could not parse intermediate certificate ExtendedKeyUsage extension",
        malformedFve.getMessage());
  }

  private static @NonNull ImmutableCTLogOptions enabledCTLog() {
    return CTLogOptions.builder().isEnabled(true).build();
  }

  private static @NonNull ImmutableCTLogOptions disabledCTLog() {
    return CTLogOptions.builder().isEnabled(false).build();
  }

  @FunctionalInterface
  private interface LeafFactory {
    X509Certificate create(TestCa ca) throws Exception;
  }

  /** A self-signed CA, standing in for a private deployment's fulcio CA. */
  private static class TestCa {
    private final X500Name name = new X500Name("CN=test-ca,O=test");
    private final KeyPair keyPair;
    private final CertificateAuthority authority;
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
      authority =
          ImmutableCertificateAuthority.builder()
              .certPath(Certificates.toCertPath(toX509(root.build(signer()))))
              .uri(URI.create("https://fulcio.test"))
              .validFor(ImmutableValidFor.builder().start(now.minus(Duration.ofHours(1))).build())
              .subject(ImmutableSubject.builder().organization("test").commonName("test").build())
              .build();
    }

    LeafBuilder leaf() throws Exception {
      return new LeafBuilder();
    }

    private class LeafBuilder {
      private final Map<ASN1ObjectIdentifier, Extension> extensions = new LinkedHashMap<>();

      LeafBuilder() throws Exception {
        ext(
            Extension.subjectAlternativeName,
            true,
            new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.com"))
                .getEncoded());
        bc(true, false);
        ku(KeyUsage.digitalSignature);
        eku(false, KeyPurposeId.id_kp_codeSigning);
      }

      LeafBuilder bc(boolean critical, boolean isCa) throws Exception {
        return ext(Extension.basicConstraints, critical, new BasicConstraints(isCa).getEncoded());
      }

      LeafBuilder ku(int usage) throws Exception {
        return ku(true, usage);
      }

      LeafBuilder ku(boolean critical, int usage) throws Exception {
        return ext(Extension.keyUsage, critical, new KeyUsage(usage).getEncoded());
      }

      LeafBuilder eku(boolean critical, KeyPurposeId... purposes) throws Exception {
        return ext(
            Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(purposes).getEncoded());
      }

      LeafBuilder without(ASN1ObjectIdentifier oid) {
        extensions.remove(oid);
        return this;
      }

      LeafBuilder ext(ASN1ObjectIdentifier oid, boolean critical, byte[] value) {
        extensions.put(oid, new Extension(oid, critical, value));
        return this;
      }

      X509Certificate build() throws Exception {
        return build(name, signer());
      }

      X509Certificate build(X500Name issuer, ContentSigner contentSigner) throws Exception {
        var builder =
            new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.TWO,
                Date.from(now.minus(Duration.ofMinutes(1))),
                Date.from(now.plus(Duration.ofMinutes(10))),
                new X500Name(""),
                newKeyPair().getPublic());
        for (var extension : extensions.values()) {
          builder.addExtension(extension);
        }
        return toX509(builder.build(contentSigner));
      }
    }

    X509Certificate issueV1Leaf() throws Exception {
      var leaf =
          new JcaX509v1CertificateBuilder(
              name,
              BigInteger.TWO,
              Date.from(now.minus(Duration.ofMinutes(1))),
              Date.from(now.plus(Duration.ofMinutes(10))),
              new X500Name("CN=v1-leaf"),
              newKeyPair().getPublic());
      return toX509(leaf.build(signer()));
    }

    CertPath issueChainWithIntermediate(byte @Nullable [] intermediateEkuBytes) throws Exception {
      var intKeyPair = newKeyPair();
      var intName = new X500Name("CN=test-intermediate,O=test");
      var intBuilder =
          new JcaX509v3CertificateBuilder(
                  name,
                  BigInteger.valueOf(3),
                  Date.from(now.minus(Duration.ofMinutes(5))),
                  Date.from(now.plus(Duration.ofMinutes(30))),
                  intName,
                  intKeyPair.getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
              .addExtension(
                  Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      if (intermediateEkuBytes != null) {
        intBuilder.addExtension(Extension.extendedKeyUsage, false, intermediateEkuBytes);
      }
      var intermediate = toX509(intBuilder.build(signer()));
      var intSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(intKeyPair.getPrivate());
      return Certificates.toCertPath(List.of(leaf().build(intName, intSigner), intermediate));
    }

    private ContentSigner signer() throws Exception {
      return new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
    }

    private static X509Certificate toX509(X509CertificateHolder holder) throws Exception {
      return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static KeyPair newKeyPair() throws Exception {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      return keyPairGenerator.generateKeyPair();
    }
  }
}
