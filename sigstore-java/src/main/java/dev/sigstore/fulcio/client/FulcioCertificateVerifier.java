/*
 * Copyright 2023 The Sigstore Authors.
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

import dev.sigstore.KeylessVerificationRequest.CertificateIdentity;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;

/** Verifier for fulcio Certificate fields. */
public class FulcioCertificateVerifier {
  private static final String FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.1";

  private static final Logger log = Logger.getLogger(FulcioCertificateVerifier.class.getName());

  /**
   * Returns {@code true} if for any of the provided certIds, all the extension fields are found in
   * the provided certificate AND they are equal.
   *
   * @param cert the certificate in question
   * @param certIds a list of potentially matching certificate parameters
   * @throws FulcioVerificationException if no matches were found or an error occurred while
   *     inspecting the certificate
   */
  public void verifyCertificateMatches(X509Certificate cert, List<CertificateIdentity> certIds)
      throws FulcioVerificationException {
    for (var certId : certIds) {
      if (certificateMatches(cert, certId)) {
        return; // we found one that matches
      }
    }
    throw new FulcioVerificationException(
        "No provided certificate identities matched values in certificate");
  }

  /* Returns true if all provided fields in certId exist in the certificate and match
   * the extensions values in the certificate. */
  private boolean certificateMatches(X509Certificate cert, CertificateIdentity certId)
      throws FulcioVerificationException {
    var san = extractSan(cert);
    var issuer = getExtensionValueRawUtf8(cert, FULCIO_ISSUER_OID);
    if (!Objects.equals(certId.getSubjectAlternativeName(), san)) {
      log.fine("san did not match (" + san + "," + certId.getSubjectAlternativeName() + ")");
      return false;
    }
    if (!Objects.equals(certId.getIssuer(), issuer)) {
      log.fine("issuer did not match (" + issuer + "," + certId.getIssuer() + ")");
      return false;
    }
    for (var otherOid : certId.getOther().keySet()) {
      var entry = getExtensionValueRawUtf8(cert, otherOid);
      if (!Objects.equals(entry, certId.getOther().get(otherOid))) {
        log.fine(
            otherOid + " did not match (" + entry + "," + certId.getOther().get(otherOid) + ")");
        return false;
      }
    }
    return true;
  }

  /* Looks for only a single SAN and extracts an email or machine id from it. If not a single SAN,
   * then errors. If not an rfc822Name(email) or URI(machine-id) then fails. */
  private String extractSan(X509Certificate cert) throws FulcioVerificationException {
    try {
      var sans = cert.getSubjectAlternativeNames();
      if (sans.size() == 0) {
        throw new FulcioVerificationException("No SANs found in fulcio certificate");
      }
      if (sans.size() > 1) {
        throw new FulcioVerificationException(
            "Fulcio ceritifcate must only have 1 SAN, but found " + sans.size());
      }
      var san = sans.stream().findFirst().get();
      var type = (Integer) san.get(0);
      if (!type.equals(GeneralName.rfc822Name)
          && !type.equals(GeneralName.uniformResourceIdentifier)) {
        throw new FulcioVerificationException(
            "Fulcio certificates SAN must be of type rfc822 or URI");
      }
      return (String) san.get(1);
    } catch (CertificateParsingException cpe) {
      throw new FulcioVerificationException("Could not parse SAN from fulcio certificate", cpe);
    }
  }

  /* Extracts the octets from an extension value and converts to utf-8 directly, it does NOT
   * account for any ASN1 encoded value. If the extension value is an ASN1 object (like an
   * ASN1 encoded string), you need to write a new extraction helper. */
  private String getExtensionValueRawUtf8(X509Certificate cert, String oid)
      throws FulcioVerificationException {
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
      throw new FulcioVerificationException(
          "Could not parse extension "
              + oid
              + " in certificate because it was not an octet string");
    } catch (IOException ioe) {
      throw new FulcioVerificationException(
          "Could not parse extension " + oid + " in certificate", ioe);
    }
  }
}
