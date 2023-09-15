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
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.bundle.BundleFactory;
import dev.sigstore.encryption.certificates.transparency.SerializationException;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import dev.sigstore.trustroot.ImmutableLogId;
import dev.sigstore.trustroot.ImmutableTransparencyLog;
import dev.sigstore.trustroot.ImmutableTransparencyLogs;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FulcioVerifierTest {
  private static String sctBase64;
  private static String certs;
  private static String certsWithEmbeddedSct;
  private static String bundleFile;

  private static SigstoreTrustedRoot trustRoot;

  @BeforeAll
  public static void loadResources() throws IOException {
    sctBase64 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/sct.base64"),
            StandardCharsets.UTF_8);
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
  public static void initTrustRoot() throws IOException, CertificateException {
    var json =
        Resources.toString(
            Resources.getResource("dev/sigstore/trustroot/trusted_root.json"),
            StandardCharsets.UTF_8);
    var builder = TrustedRoot.newBuilder();
    JsonFormat.parser().merge(json, builder);

    trustRoot = SigstoreTrustedRoot.from(builder.build());
  }

  @Test
  public void detachedSctNotSupported() throws Exception {
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var ex =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () -> fulcioVerifier.verifySct(signingCertificate, signingCertificate.getCertPath()));
    Assertions.assertEquals(
        "Detached SCTs are not supported for validating certificates", ex.getMessage());
  }

  @Test
  public void testVerifySct_nullCtLogKey()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    var signingCertificate =
        SigningCertificate.newSigningCertificate(certsWithEmbeddedSct, sctBase64);
    var fulcioVerifier =
        FulcioVerifier.newFulcioVerifier(
            trustRoot.getCAs(),
            ImmutableTransparencyLogs.builder()
                .addAllTransparencyLogs(Collections.emptyList())
                .build());

    try {
      fulcioVerifier.verifySigningCertificate(signingCertificate);
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals("No ct logs were provided to verifier", fve.getMessage());
    }
  }

  @Test
  public void testVerifySct_noSct() throws Exception {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, null);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    try {
      fulcioVerifier.verifySct(signingCertificate, signingCertificate.getCertPath());
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals("No valid SCTs were found during verification", fve.getMessage());
    }
  }

  @Test
  public void validSigningCertAndEmbeddedSct() throws Exception {
    var signingCertificate = SigningCertificate.newSigningCertificate(certsWithEmbeddedSct, null);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    fulcioVerifier.verifySigningCertificate(signingCertificate);
  }

  @Test
  public void validBundle() throws Exception {
    var bundle = BundleFactory.readBundle(new StringReader(bundleFile));
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustRoot);

    Assertions.assertEquals(1, bundle.getCertPath().getCertificates().size());
    fulcioVerifier.verifySigningCertificate(SigningCertificate.from(bundle.getCertPath()));
  }

  @Test
  public void invalidEmbeddedSct() throws Exception {
    var signingCertificate = SigningCertificate.newSigningCertificate(certsWithEmbeddedSct, null);
    var fulcioVerifier =
        FulcioVerifier.newFulcioVerifier(
            trustRoot.getCAs(),
            ImmutableTransparencyLogs.builder()
                .addTransparencyLog(
                    ImmutableTransparencyLog.builder()
                        .from(trustRoot.getCTLogs().all().get(0))
                        .logId(
                            ImmutableLogId.builder()
                                .keyId("abcd".getBytes(StandardCharsets.UTF_8))
                                .build())
                        .build())
                .build());

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class,
            () -> fulcioVerifier.verifySct(signingCertificate, signingCertificate.getCertPath()));
    Assertions.assertEquals("No valid SCTs were found, all(1) SCTs were invalid", fve.getMessage());
  }
}
