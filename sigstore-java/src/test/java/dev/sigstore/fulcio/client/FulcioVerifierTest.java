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
import dev.sigstore.encryption.certificates.transparency.SerializationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FulcioVerifierTest {
  private static String sctBase64;
  private static String certs;
  private static byte[] fulcioRoot;
  private static byte[] ctfePub;
  private static byte[] badCtfePub;
  private static String certsWithEmbeddedSct;

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

    fulcioRoot =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/fulcio.crt.pem"));
    ctfePub =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/ctfe-ec.pub"));
    badCtfePub =
        Resources.toByteArray(Resources.getResource("dev/sigstore/samples/keys/test-rsa.pub"));

    certsWithEmbeddedSct =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
            StandardCharsets.UTF_8);
  }

  @Test
  public void validSigningCertAndDetachedSct()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          FulcioVerificationException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, ctfePub);

    fulcioVerifier.verifyCertChain(signingCertificate);
    fulcioVerifier.verifySct(signingCertificate);
  }

  @Test
  public void testVerifySct_nullCtLogKey()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, null);

    try {
      fulcioVerifier.verifySct(signingCertificate);
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals("No ct-log public key was provided to verifier", fve.getMessage());
    }
  }

  @Test
  public void testVerifySct_noSct()
      throws SerializationException, CertificateException, IOException,
          InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchAlgorithmException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, null);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, ctfePub);

    try {
      fulcioVerifier.verifySct(signingCertificate);
      Assertions.fail();
    } catch (FulcioVerificationException fve) {
      Assertions.assertEquals(
          "No detached or embedded SCTs were found to verify", fve.getMessage());
    }
  }

  @Test
  public void validSigningCertAndEmbeddedSct()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          FulcioVerificationException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certsWithEmbeddedSct, null);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, ctfePub);

    fulcioVerifier.verifyCertChain(signingCertificate);
    fulcioVerifier.verifySct(signingCertificate);
  }

  @Test
  public void invalidEmbeddedSct()
      throws SerializationException, CertificateException, IOException,
          InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchAlgorithmException,
          FulcioVerificationException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certsWithEmbeddedSct, null);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, badCtfePub);

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class, () -> fulcioVerifier.verifySct(signingCertificate));
    Assertions.assertEquals(
        "Expecting at least one valid sct, but found 0 valid and 1 invalid scts", fve.getMessage());
  }

  @Test
  public void invalidDetachedSct()
      throws SerializationException, CertificateException, IOException,
          InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchAlgorithmException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var fulcioVerifier = FulcioVerifier.newFulcioVerifier(fulcioRoot, badCtfePub);

    var fve =
        Assertions.assertThrows(
            FulcioVerificationException.class, () -> fulcioVerifier.verifySct(signingCertificate));
    // TODO: this error message could probably use some work
    Assertions.assertEquals("SCT could not be verified because UNKNOWN_LOG", fve.getMessage());
  }
}
