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
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CertificatesTest {
  static final String CERT_CHAIN = "dev/sigstore/samples/certs/cert.pem";
  static final String CERT = "dev/sigstore/samples/certs/cert-single.pem";
  static final String CERT_GH = "dev/sigstore/samples/certs/cert-githuboidc.pem";

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

  @Test
  public void fromDer() throws Exception {
    var derCert =
        Base64.decode(
            "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==");
    Assertions.assertNotNull(Certificates.fromDer(derCert));
  }

  @Test
  public void fromDer_certPath() throws Exception {
    List<byte[]> certs = new ArrayList<>(2);
    certs.add(
        0,
        Base64.decode(
            "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="));
    certs.add(
        1,
        Base64.decode(
            "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"));
    Assertions.assertEquals(2, Certificates.fromDer(certs).getCertificates().size());
  }

  @Test
  public void toCertPath() throws Exception {
    var cert =
        Certificates.fromDer(
            Base64.decode(
                "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="));
    var certPath = Certificates.toCertPath(cert);
    Assertions.assertEquals(1, certPath.getCertificates().size());
    Assertions.assertEquals(cert, certPath.getCertificates().get(0));
  }

  @Test
  public void appendCertPath() throws Exception {
    var parent =
        Certificates.fromPemChain(Resources.toByteArray(Resources.getResource(CERT_CHAIN)));
    var child = Certificates.fromPem(Resources.toByteArray(Resources.getResource(CERT_GH)));

    Assertions.assertEquals(2, parent.getCertificates().size());
    var appended = Certificates.appendCertPath(parent, child);

    Assertions.assertEquals(3, appended.getCertificates().size());
    Assertions.assertEquals(child, appended.getCertificates().get(0));
    Assertions.assertEquals(parent.getCertificates().get(0), appended.getCertificates().get(1));
    Assertions.assertEquals(parent.getCertificates().get(1), appended.getCertificates().get(2));
  }

  @Test
  public void trimParent() throws Exception {
    var certPath =
        Certificates.fromPemChain(Resources.toByteArray(Resources.getResource(CERT_CHAIN)));
    var parent =
        CertificateFactory.getInstance("X.509")
            .generateCertPath(List.of(certPath.getCertificates().get(1)));

    var trimmed = Certificates.trimParent(certPath, parent);

    Assertions.assertEquals(1, trimmed.getCertificates().size());
    Assertions.assertEquals(certPath.getCertificates().get(0), trimmed.getCertificates().get(0));
  }

  @Test
  public void containsParent() throws Exception {
    var certPath =
        Certificates.fromPemChain(Resources.toByteArray(Resources.getResource(CERT_CHAIN)));
    var parent =
        CertificateFactory.getInstance("X.509")
            .generateCertPath(List.of(certPath.getCertificates().get(1)));
    var cert = Certificates.fromPemChain(Resources.toByteArray(Resources.getResource(CERT)));

    Assertions.assertTrue(Certificates.containsParent(certPath, parent));
    Assertions.assertFalse(Certificates.containsParent(cert, certPath));
    Assertions.assertTrue(Certificates.containsParent(certPath, certPath));
    Assertions.assertTrue(Certificates.containsParent(cert, cert));
  }

  @Test
  public void isSelfSigned() throws Exception {
    var certPath =
        Certificates.fromPemChain(Resources.toByteArray(Resources.getResource(CERT_CHAIN)));
    var cert = Certificates.fromPem(Resources.toByteArray(Resources.getResource(CERT)));

    Assertions.assertTrue(Certificates.isSelfSigned(certPath));
    Assertions.assertFalse(Certificates.isSelfSigned(cert));
  }
}
