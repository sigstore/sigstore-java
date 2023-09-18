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
import com.google.common.collect.ImmutableList;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class Certificates {

  private static final String SCT_X509_OID = "1.3.6.1.4.1.11129.2.4.2";

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

  /** Convert a single der encoded cert to Certificate. */
  public static Certificate fromDer(byte[] cert) throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return cf.generateCertificate(new ByteArrayInputStream(cert));
  }

  /** Convert a lit of der encoded certs to CertPath. */
  public static CertPath fromDer(List<byte[]> certChain) throws CertificateException {
    List<Certificate> certificates = new ArrayList<>(certChain.size());
    for (var cert : certChain) {
      certificates.add(fromDer(cert));
    }
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return cf.generateCertPath(certificates);
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

  /** Converts a single X509Certificate to a {@link CertPath}. */
  public static CertPath toCertPath(Certificate certificate) throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return cf.generateCertPath(Collections.singletonList(certificate));
  }

  /** Appends an CertPath to another {@link CertPath} as children. */
  public static CertPath appendCertPath(CertPath parent, Certificate child)
      throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> certs =
        ImmutableList.<Certificate>builder().add(child).addAll(parent.getCertificates()).build();
    return cf.generateCertPath(certs);
  }

  /**
   * Trims a parent CertPath from a provided CertPath. This is intended to be used to trim trusted
   * root and intermediates from a full CertPath to reveal just the untrusted parts which can be
   * distributed as part of a signature tuple or bundle.
   *
   * @param certPath a certificate path to trim from
   * @param parentPath the parent certPath to trim off the full certPath
   * @return a trimmed path
   * @throws IllegalArgumentException if the trimPath is not a parent of the certPath or if they are
   *     the same length
   * @throws CertificateException if an error occurs during CertPath construction
   */
  public static CertPath trimParent(CertPath certPath, CertPath parentPath)
      throws CertificateException {
    if (!containsParent(certPath, parentPath)) {
      throw new IllegalArgumentException("trim path was not the parent of the provider chain");
    }
    var certs = certPath.getCertificates();
    var parent = parentPath.getCertificates();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return cf.generateCertPath(certs.subList(0, certs.size() - parent.size()));
  }

  /** Check if a parent certpath is the suffix of a certpath */
  public static boolean containsParent(CertPath certPath, CertPath parentPath) {
    var certs = certPath.getCertificates();
    var parent = parentPath.getCertificates();
    return parent.size() <= certs.size()
        && certs.subList(certs.size() - parent.size(), certs.size()).equals(parent);
  }

  /**
   * Find and return any SCTs embedded in a certificate.
   *
   * @param certificate the certificate with embedded scts
   * @return a byte array containing any number of embedded scts
   */
  public static Optional<byte[]> getEmbeddedSCTs(Certificate certificate) {
    return Optional.ofNullable(((X509Certificate) certificate).getExtensionValue(SCT_X509_OID));
  }

  /** Check if a certificate is self-signed. */
  public static boolean isSelfSigned(Certificate certificate) {
    return ((X509Certificate) certificate)
        .getIssuerX500Principal()
        .equals(((X509Certificate) certificate).getSubjectX500Principal());
  }

  /** Check if the root of a CertPath is self-signed */
  public static boolean isSelfSigned(CertPath certPath) {
    return isSelfSigned(certPath.getCertificates().get(certPath.getCertificates().size() - 1));
  }

  public static X509Certificate getLeaf(CertPath certPath) {
    return (X509Certificate) certPath.getCertificates().get(0);
  }
}
