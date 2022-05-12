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
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import org.conscrypt.ct.SerializationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SigningCertificateTest {
  @Test
  public void TestDecode() throws SerializationException, IOException, CertificateException {
    String sctBase64 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/sct.base64"),
            Charset.defaultCharset());
    String certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/cert.pem"),
            Charset.defaultCharset());

    SigningCertificate.newSigningCertificate(certs, sctBase64);
  }

  @Test
  public void TestDecode_DerCert() throws CertificateException, IOException {
    String certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/certs/cert.der"), Charset.defaultCharset());
    try {
      SigningCertificate.decodeCerts(certs);
      Assertions.fail("DER certificate was unexpectedly successfully parsed");
    } catch (CertificateParsingException cpe) {
      Assertions.assertEquals(
          "no valid PEM certificates were found in response from Fulcio", cpe.getMessage());
    }
  }
}
