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
import com.google.protobuf.ByteString;
import dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT;
import dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT;
import dev.sigstore.testing.grpc.GrpcTypes;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Base64;
import org.conscrypt.ct.SerializationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SigningCertificateTest {
  @Test
  public void testDecode() throws SerializationException, IOException, CertificateException {
    String sctBase64 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/sct.base64"),
            StandardCharsets.UTF_8);
    String certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/cert.pem"),
            StandardCharsets.UTF_8);

    var signingCert = SigningCertificate.newSigningCertificate(certs, sctBase64);
    Assertions.assertTrue(signingCert.getDetachedSct().isPresent());
    Assertions.assertEquals(2, signingCert.getCertificates().size());
  }

  @Test
  public void testDecode_embedded()
      throws SerializationException, IOException, CertificateException {
    String certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
            StandardCharsets.UTF_8);

    var signingCert = SigningCertificate.newSigningCertificate(certs, null);
    Assertions.assertTrue(signingCert.hasEmbeddedSct());
    Assertions.assertEquals(3, signingCert.getCertificates().size());
  }

  @Test
  public void testDecode_derCert() throws CertificateException, IOException {
    String certs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/certs/cert.der"), StandardCharsets.UTF_8);
    try {
      SigningCertificate.decodeCerts(certs);
      Assertions.fail("DER certificate was unexpectedly successfully parsed");
    } catch (CertificateParsingException cpe) {
      Assertions.assertEquals(
          "no valid PEM certificates were found in response from Fulcio", cpe.getMessage());
    }
  }

  @Test
  public void testDecode_grpc() throws IOException, CertificateException, SerializationException {
    var certs =
        GrpcTypes.PemToCertificateChain(
            Resources.toString(
                Resources.getResource("dev/sigstore/samples/fulcio-response/valid/cert.pem"),
                StandardCharsets.UTF_8));
    String sctBase64 =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/fulcio-response/valid/sct.base64"),
            StandardCharsets.UTF_8);
    var signingCert =
        SigningCertificate.newSigningCertificate(
            SigningCertificateDetachedSCT.newBuilder()
                .setChain(certs)
                .setSignedCertificateTimestamp(
                    ByteString.copyFrom(Base64.getDecoder().decode(sctBase64)))
                .build());
    Assertions.assertTrue(signingCert.getDetachedSct().isPresent());
    Assertions.assertEquals(2, signingCert.getCertificates().size());
  }

  @Test
  public void testDecode_embeddedGrpc()
      throws IOException, CertificateException, SerializationException {
    var certs =
        GrpcTypes.PemToCertificateChain(
            Resources.toString(
                Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
                StandardCharsets.UTF_8));
    var signingCert =
        SigningCertificate.newSigningCertificate(
            SigningCertificateEmbeddedSCT.newBuilder().setChain(certs).build());
    Assertions.assertTrue(signingCert.hasEmbeddedSct());
    Assertions.assertEquals(3, signingCert.getCertificates().size());
  }
}
