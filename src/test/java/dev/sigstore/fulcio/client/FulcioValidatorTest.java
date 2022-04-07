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
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.conscrypt.ct.SerializationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FulcioValidatorTest {
  private String sctBase64;
  private String certs;
  private byte[] fulcioRoot;
  private byte[] ctfePub;

  @Before
  public void loadResources() throws IOException {
    sctBase64 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/sct.base64"),
            Charset.defaultCharset());
    certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/cert.pem"),
            Charset.defaultCharset());

    fulcioRoot =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/fulcio.crt.pem"));
    ctfePub =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/ctfe.pub"));
  }

  @Test
  public void validSigningCertAndSct()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException, FulcioValidationException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var fulcioValidator = FulcioValidator.newFulcioValidator(fulcioRoot, ctfePub);

    fulcioValidator.validateCertChain(signingCertificate);
    fulcioValidator.validateSct(signingCertificate);
  }

  @Test
  public void testValidateSct_nullCtLogKey()
      throws IOException, SerializationException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, sctBase64);
    var fulcioValidator = FulcioValidator.newFulcioValidator(fulcioRoot, null);

    try {
      fulcioValidator.validateSct(signingCertificate);
      Assert.fail();
    } catch (FulcioValidationException fve) {
      Assert.assertEquals("No ct-log public key was provided to validator", fve.getMessage());
    }
  }

  @Test
  public void testValidateSct_noSct()
      throws SerializationException, CertificateException, IOException,
          InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchAlgorithmException {
    var signingCertificate = SigningCertificate.newSigningCertificate(certs, null);
    var fulcioValidator = FulcioValidator.newFulcioValidator(fulcioRoot, ctfePub);

    try {
      fulcioValidator.validateSct(signingCertificate);
      Assert.fail();
    } catch (FulcioValidationException fve) {
      Assert.assertEquals("No SCT was found to validate", fve.getMessage());
    }
  }
}
