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
import dev.sigstore.bundle.Bundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.trustroot.ImmutableLogId;
import dev.sigstore.trustroot.ImmutableTransparencyLog;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
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
    var json = Resources.getResource("dev/sigstore/trustroot/trusted_root.json").openStream();
    trustRoot = SigstoreTrustedRoot.from(json);
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
      fulcioVerifier.verifySct(signingCertificate);
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
            FulcioVerificationException.class, () -> fulcioVerifier.verifySct(signingCertificate));
    Assertions.assertEquals("No valid SCTs were found, all(1) SCTs were invalid", fve.getMessage());
  }
}
