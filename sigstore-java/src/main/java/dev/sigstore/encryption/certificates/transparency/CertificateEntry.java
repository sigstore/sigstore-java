/*
 * Copyright 2022 The Sigstore Authors.
 * Copyright 2015 The Android Open Source Project.
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
package dev.sigstore.encryption.certificates.transparency;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

/**
 * CertificateEntry structure. This structure describes part of the data which is signed over in
 * SCTs. It is not defined by the RFC6962, but it is useful to have.
 *
 * <p>It's definition would be : struct { LogEntryType entry_type; select(entry_type) { case
 * x509_entry: ASN.1Cert; case precert_entry: PreCert; } signed_entry; } CertificateEntry;
 */
public class CertificateEntry {
  public enum LogEntryType {
    X509_ENTRY,
    PRECERT_ENTRY
  }

  private final LogEntryType entryType;

  // Only used when entryType is LOG_ENTRY_TYPE_PRECERT
  private final byte[] issuerKeyHash;

  /* If entryType == PRECERT_ENTRY, this is the encoded TBS of the precertificate.
  If entryType == X509_ENTRY, this is the encoded leaf certificate. */
  private final byte[] certificate;

  private CertificateEntry(LogEntryType entryType, byte[] certificate, byte[] issuerKeyHash) {
    if (entryType == LogEntryType.PRECERT_ENTRY && issuerKeyHash == null) {
      throw new IllegalArgumentException("issuerKeyHash missing for precert entry.");
    } else if (entryType == LogEntryType.X509_ENTRY && issuerKeyHash != null) {
      throw new IllegalArgumentException("unexpected issuerKeyHash for X509 entry.");
    }

    if (issuerKeyHash != null && issuerKeyHash.length != CTConstants.ISSUER_KEY_HASH_LENGTH) {
      throw new IllegalArgumentException("issuerKeyHash must be 32 bytes long");
    }

    this.entryType = entryType;
    this.issuerKeyHash = issuerKeyHash;
    this.certificate = certificate;
  }

  /**
   * Creates a CertificateEntry with type PRECERT_ENTRY
   *
   * @throws IllegalArgumentException if issuerKeyHash isn't 32 bytes
   */
  public static CertificateEntry createForPrecertificate(
      byte[] tbsCertificate, byte[] issuerKeyHash) {
    return new CertificateEntry(LogEntryType.PRECERT_ENTRY, tbsCertificate, issuerKeyHash);
  }

  public static CertificateEntry createForPrecertificate(
      X509Certificate leaf, X509Certificate issuer) throws CertificateException {
    try {
      if (!leaf.getNonCriticalExtensionOIDs().contains(CTConstants.X509_SCT_LIST_OID)) {
        throw new CertificateException("Certificate does not contain embedded signed timestamps");
      }

      var bcCert = Certificate.getInstance(leaf.getEncoded());
      var extensions = bcCert.getTBSCertificate().getExtensions();

      var filteredExtensionsList =
          Arrays.stream(extensions.getExtensionOIDs())
              .sequential()
              .filter(oid -> !oid.getId().equals(CTConstants.X509_SCT_LIST_OID))
              .filter(oid -> !oid.getId().equals(CTConstants.POISON_EXTENSION_OID))
              .map(extensions::getExtension)
              .toArray(Extension[]::new);

      var filteredExtensions = new Extensions(filteredExtensionsList);

      var tbs = bcCert.getTBSCertificate();

      var tbsGenerator = new V3TBSCertificateGenerator();
      tbsGenerator.setSerialNumber(tbs.getSerialNumber());
      tbsGenerator.setSignature(tbs.getSignature());
      tbsGenerator.setIssuer(tbs.getIssuer());
      tbsGenerator.setStartDate(tbs.getStartDate());
      tbsGenerator.setEndDate(tbs.getEndDate());
      tbsGenerator.setSubject(tbs.getSubject());
      tbsGenerator.setSubjectPublicKeyInfo(tbs.getSubjectPublicKeyInfo());
      tbsGenerator.setIssuerUniqueID((DERBitString) tbs.getIssuerUniqueId());
      tbsGenerator.setSubjectUniqueID((DERBitString) tbs.getSubjectUniqueId());
      tbsGenerator.setExtensions(filteredExtensions);

      var precertTbs = tbsGenerator.generateTBSCertificate();

      byte[] issuerKey = issuer.getPublicKey().getEncoded();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(issuerKey);
      byte[] issuerKeyHash = md.digest();

      return createForPrecertificate(precertTbs.getEncoded(), issuerKeyHash);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is guaranteed to be available
      throw new RuntimeException(e);
    } catch (IOException ex) {
      throw new CertificateException("Could not create precertificate", ex);
    }
  }

  public static CertificateEntry createForX509Certificate(byte[] x509Certificate) {
    return new CertificateEntry(LogEntryType.X509_ENTRY, x509Certificate, null);
  }

  public static CertificateEntry createForX509Certificate(X509Certificate cert)
      throws CertificateEncodingException {
    return createForX509Certificate(cert.getEncoded());
  }

  public LogEntryType getEntryType() {
    return entryType;
  }

  public byte[] getCertificate() {
    return certificate;
  }

  public byte[] getIssuerKeyHash() {
    return issuerKeyHash;
  }

  /** TLS encode the CertificateEntry structure. */
  public void encode(OutputStream output) throws SerializationException {
    Serialization.writeNumber(output, entryType.ordinal(), CTConstants.LOG_ENTRY_TYPE_LENGTH);
    if (entryType == LogEntryType.PRECERT_ENTRY) {
      Serialization.writeFixedBytes(output, issuerKeyHash);
    }
    Serialization.writeVariableBytes(output, certificate, CTConstants.CERTIFICATE_LENGTH_BYTES);
  }
}
