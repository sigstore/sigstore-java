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

import com.google.api.client.util.PemReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.util.ArrayList;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class Certificates {

  /** Convert a certificate to a PEM encoded certificate. */
  public static String toPemString(Certificate cert) throws IOException {
    var certWriter = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(certWriter)) {
      pemWriter.writeObject(cert);
      pemWriter.flush();
    }
    return certWriter.toString();
  }

  /** Convert a certificate to a PEM encoded certificate. */
  public static byte[] toPemBytes(Certificate cert) throws IOException {
    return toPemString(cert).getBytes(StandardCharsets.UTF_8);
  }

  public static Certificate fromPem(String cert) throws CertificateException {
    var certs = fromPemChain(cert).getCertificates();
    if (certs.size() > 1) {
      throw new CertificateException(
          "Found chain of length " + certs.size() + " when parsing a single cert");
    }
    return certs.get(0);
  }

  public static Certificate fromPem(byte[] cert) throws CertificateException {
    return fromPem(new String(cert, StandardCharsets.UTF_8));
  }

  public static Certificate fromDer(byte[] cert) throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return cf.generateCertificate(new ByteArrayInputStream(cert));
  }

  /** Convert a CertPath to a PEM encoded certificate chain. */
  public static String toPemString(CertPath certs) throws IOException {
    var certWriter = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(certWriter)) {
      for (var cert : certs.getCertificates()) {
        pemWriter.writeObject(cert);
      }
      pemWriter.flush();
    }
    return certWriter.toString();
  }

  /** Convert a CertPath to a PEM encoded certificate chain. */
  public static byte[] toPemBytes(CertPath certs) throws IOException {
    return toPemString(certs).getBytes(StandardCharsets.UTF_8);
  }

  /** Convert a PEM encoded certificate chain to a {@link CertPath}. */
  public static CertPath fromPemChain(String certs) throws CertificateException {
    PemReader pemReader = null;
    try {
      pemReader = new PemReader(new StringReader(certs));
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ArrayList<X509Certificate> certList = new ArrayList<>();
      while (true) {
        try {
          PemReader.Section section = pemReader.readNextSection();
          if (section == null) {
            break;
          }
          byte[] certBytes = section.getBase64DecodedBytes();
          certList.add(
              (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
        } catch (IOException | IllegalArgumentException ioe) {
          throw new CertificateParsingException("Error reading PEM section in cert chain", ioe);
        }
      }
      if (certList.isEmpty()) {
        throw new CertificateParsingException("no valid PEM certificates were found");
      }
      return cf.generateCertPath(certList);
    } finally {
      if (pemReader != null) {
        try {
          pemReader.close();
        } catch (IOException e) {
          // ignored
        }
      }
    }
  }

  /** Convert a PEM encoded certificate chain to a {@link CertPath}. */
  public static CertPath fromPemChain(byte[] certs) throws CertificateException {
    return fromPemChain(new String(certs, StandardCharsets.UTF_8));
  }
}
