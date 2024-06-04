/*
 * Copyright 2024 The Sigstore Authors.
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

import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.VerificationOptions.UncheckedCertificateException;
import dev.sigstore.strings.StringMatcher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Hex;
import org.immutables.value.Value.Immutable;

@Immutable
public abstract class FulcioCertificateMatcher implements CertificateMatcher {

  /** Match against the identity token issuer */
  public abstract StringMatcher getIssuer();

  /** Match against the identity token subject/email */
  public abstract StringMatcher getSubjectAlternativeName();

  /**
   * For OIDs with raw string entries. This is non-standard, but older fulcio OID extensions values
   * use it.
   */
  public abstract Map<String, StringMatcher> getOidRawStrings();

  /**
   * For OIDs with DER encoded ASN.1 string entries. This is the standard for strings values as OID
   * extensions.
   */
  public abstract Map<String, StringMatcher> getOidDerAsn1Strings();

  /**
   * For comparing raw bytes of the full ASN.1 object extension value as defined by EXTENSION in <a
   * href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1">rfc5280</a>
   *
   * <p>The key is the oid string (ex: 1.2.3.4.5) and the value is a raw byte array. Matching is a
   * direct byte array equality check with no mutations on the extension value.
   */
  public abstract Map<String, byte[]> getOidBytes();

  private static final Logger log = Logger.getLogger(FulcioCertificateMatcher.class.getName());
  private static final String FULCIO_ISSUER_OLD_OID = "1.3.6.1.4.1.57264.1.1";
  private static final String FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.8";

  private static void logMismatch(String oid, String expected, String actual) {
    log.fine(oid + " value did not match - expected:" + expected + ", actual:" + actual);
  }

  @Override
  public String toString() {
    String str = "{issuer:" + getIssuer() + ",san:" + getSubjectAlternativeName();
    if (!getOidRawStrings().isEmpty()) {
      str +=
          ",oidRawStrings:{"
              + getOidRawStrings().entrySet().stream()
                  .map(e -> e.getKey() + ":" + e.getValue())
                  .collect(Collectors.joining(","))
              + "}";
    }
    if (!getOidDerAsn1Strings().isEmpty()) {
      str +=
          ",oidDerAsn1Strings:{"
              + getOidDerAsn1Strings().entrySet().stream()
                  .map(e -> e.getKey() + ":" + e.getValue())
                  .collect(Collectors.joining(","))
              + "}";
    }
    if (!getOidBytes().isEmpty()) {
      str +=
          ",oidBytes:{"
              + getOidBytes().entrySet().stream()
                  .map(e -> e.getKey() + ":" + hexOrNull(e.getValue()))
                  .collect(Collectors.joining(","))
              + "}";
    }
    return str + "}";
  }

  /* Returns true if ALL provided fields exist in the certificate and match the extensions values in the certificate. */
  @Override
  public boolean test(X509Certificate certificate) throws UncheckedCertificateException {
    try {
      var san = extractSan(certificate);
      if (!getSubjectAlternativeName().test(san)) {
        logMismatch("san", getSubjectAlternativeName().toString(), san);
        return false;
      }
      var issuer = extractIssuer(certificate);
      if (!getIssuer().test(issuer)) {
        logMismatch("issuer", getIssuer().toString(), issuer);
        return false;
      }
      for (var rawOid : getOidRawStrings().keySet()) {
        var entry = getExtensionValueRawUtf8(certificate, rawOid);
        var expected = getOidRawStrings().get(rawOid);
        if (!expected.test(entry)) {
          logMismatch(rawOid, expected.toString(), entry);
          return false;
        }
      }
      for (var derOid : getOidDerAsn1Strings().keySet()) {
        var entry = getExtensionValueDerAsn1Utf8(certificate, derOid);
        var expected = getOidDerAsn1Strings().get(derOid);
        if (!expected.test(entry)) {
          logMismatch(derOid, expected.toString(), entry);
          return false;
        }
      }
      for (var bytesOid : getOidBytes().keySet()) {
        var entry = certificate.getExtensionValue(bytesOid);
        var expected = getOidBytes().get(bytesOid);
        if (!Arrays.equals(entry, expected)) {
          logMismatch(bytesOid, hexOrNull(expected), hexOrNull(entry));
          return false;
        }
      }
      return true;
    } catch (CertificateException ce) {
      throw new UncheckedCertificateException("Failed to process certificate ", ce);
    }
  }

  /* Looks for only a single SAN and extracts an email or machine id from it. If not a single SAN,
   * then errors. If not an rfc822Name(email) or URI(machine-id) then fails. */
  private String extractSan(X509Certificate cert) throws CertificateParsingException {
    try {
      var sans = cert.getSubjectAlternativeNames();
      if (sans.size() == 0) {
        throw new CertificateParsingException("No SANs found in fulcio certificate");
      }
      if (sans.size() > 1) {
        throw new CertificateParsingException(
            "Fulcio certificate must only have 1 SAN, but found " + sans.size());
      }
      var san = sans.stream().findFirst().get();
      var type = (Integer) san.get(0);
      if (!type.equals(GeneralName.rfc822Name)
          && !type.equals(GeneralName.uniformResourceIdentifier)) {
        throw new CertificateParsingException(
            "Fulcio certificates SAN must be of type rfc822 or URI");
      }
      return (String) san.get(1);
    } catch (CertificateParsingException cpe) {
      throw new CertificateParsingException("Could not parse SAN from fulcio certificate", cpe);
    }
  }

  private String extractIssuer(X509Certificate cert) throws CertificateParsingException {
    var issuer = getExtensionValueDerAsn1Utf8(cert, FULCIO_ISSUER_OID);
    if (issuer == null) {
      issuer = getExtensionValueRawUtf8(cert, FULCIO_ISSUER_OLD_OID);
    }
    if (issuer == null) {
      throw new CertificateParsingException("No issuer found in fulcio certificate");
    }
    return issuer;
  }

  /* Extracts the octets from an extension value and converts to utf-8 directly, it does NOT
   * account for any ASN1 encoded value. If the extension value is an ASN1 object (like an
   * ASN1 encoded string), you need to write a new extraction helper. */
  private String getExtensionValueRawUtf8(X509Certificate cert, String oid)
      throws CertificateParsingException {
    byte[] extensionValue = cert.getExtensionValue(oid);

    if (extensionValue == null) {
      return null;
    }
    try {
      ASN1Primitive derObject = ASN1Sequence.fromByteArray(cert.getExtensionValue(oid));
      if (derObject instanceof DEROctetString) {
        DEROctetString derOctetString = (DEROctetString) derObject;
        // this is unusual, but the octet is a raw utf8 string in fulcio land (no prefix of type)
        // and not an ASN1 object.
        return new String(derOctetString.getOctets(), StandardCharsets.UTF_8);
      }
      throw new CertificateParsingException(
          "Could not parse extension "
              + oid
              + " in certificate because it was not a properly formatted extension sequence");
    } catch (IOException ioe) {
      throw new CertificateParsingException(
          "Could not parse extension " + oid + " in certificate", ioe);
    }
  }

  /* Extracts a DER-encoded ASN.1 String from an extension value */
  private String getExtensionValueDerAsn1Utf8(X509Certificate cert, String oid)
      throws CertificateParsingException {
    byte[] extensionValue = cert.getExtensionValue(oid);

    if (extensionValue == null) {
      return null;
    }
    try {
      ASN1Primitive derObject = ASN1Sequence.fromByteArray(cert.getExtensionValue(oid));
      if (derObject instanceof DEROctetString) {
        DEROctetString derOctetString = (DEROctetString) derObject;

        ASN1Primitive derString = ASN1Sequence.fromByteArray(derOctetString.getOctets());
        if (derString instanceof ASN1String) {
          return ((ASN1String) derString).getString();
        } else {
          throw new CertificateParsingException(
              "Could not parse extension "
                  + oid
                  + " in certificate because it was not a DER encoded ASN.1 string");
        }
      }
      throw new CertificateParsingException(
          "Could not parse extension "
              + oid
              + " in certificate because it was not a properly formatted extension sequence");
    } catch (IOException ioe) {
      throw new CertificateParsingException(
          "Could not parse extension " + oid + " in certificate", ioe);
    }
  }

  private String hexOrNull(byte[] bytes) {
    if (bytes == null) {
      return "NULL";
    }
    return "'hex: " + Hex.toHexString(bytes) + "'";
  }
}
