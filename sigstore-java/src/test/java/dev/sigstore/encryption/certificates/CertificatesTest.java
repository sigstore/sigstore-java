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
package dev.sigstore.encryption.certificates;

import com.google.common.io.Resources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CertificatesTest {
  static final String CERT_CHAIN = "dev/sigstore/samples/certs/cert.pem";
  static final String CERT = "dev/sigstore/samples/certs/cert-single.pem";

  @Test
  public void testCertificateTranslation() throws IOException, CertificateException {
    var pemStringSrc = Resources.toString(Resources.getResource(CERT), StandardCharsets.UTF_8);
    var pemBytesSrc = Resources.toByteArray(Resources.getResource(CERT));
    var certFromBytes = Certificates.fromPem(pemBytesSrc);

    var pemString = Certificates.toPemString(certFromBytes);
    var certFromString = Certificates.fromPem(pemString);

    var pemBytes = Certificates.toPemBytes(certFromString);

    Assertions.assertEquals(certFromBytes, certFromString);
    Assertions.assertArrayEquals(pemBytesSrc, pemBytes);
    Assertions.assertEquals(pemStringSrc, pemString);
  }

  @Test
  public void fromPem_stringFailure() throws IOException {
    var pemString = Resources.toString(Resources.getResource(CERT_CHAIN), StandardCharsets.UTF_8);
    Assertions.assertThrows(CertificateException.class, () -> Certificates.fromPem(pemString));
  }

  @Test
  public void fromPem_garbage() throws IOException {
    var pemString = "garbage";
    Assertions.assertThrows(CertificateException.class, () -> Certificates.fromPem(pemString));
  }

  @Test
  public void fromPem_byteFailure() throws IOException {
    var pemBytes = Resources.toByteArray(Resources.getResource(CERT_CHAIN));
    Assertions.assertThrows(CertificateException.class, () -> Certificates.fromPem(pemBytes));
  }

  @Test
  public void testCertChainTranslation() throws IOException, CertificateException {
    var pemStringSrc =
        Resources.toString(Resources.getResource(CERT_CHAIN), StandardCharsets.UTF_8);
    var pemBytesSrc = Resources.toByteArray(Resources.getResource(CERT_CHAIN));
    var certFromBytes = Certificates.fromPemChain(pemBytesSrc);

    var pemString = Certificates.toPemString(certFromBytes);
    var certFromString = Certificates.fromPemChain(pemString);

    var pemBytes = Certificates.toPemBytes(certFromString);

    Assertions.assertEquals(certFromBytes, certFromString);
    Assertions.assertArrayEquals(pemBytesSrc, pemBytes);
    Assertions.assertEquals(pemStringSrc, pemString);
  }

  @Test
  public void fromPemChain_string() throws IOException, CertificateException {
    var pemString = Resources.toString(Resources.getResource(CERT), StandardCharsets.UTF_8);
    Assertions.assertEquals(1, Certificates.fromPemChain(pemString).getCertificates().size());
  }

  @Test
  public void fromPemChain_byte() throws IOException, CertificateException {
    var pemBytes = Resources.toByteArray(Resources.getResource(CERT));
    Assertions.assertEquals(1, Certificates.fromPemChain(pemBytes).getCertificates().size());
  }

  @Test
  public void fromPemChain_garbage() throws IOException {
    var pemString = "garbage";
    Assertions.assertThrows(CertificateException.class, () -> Certificates.fromPemChain(pemString));
  }
}
