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

import com.google.common.annotations.VisibleForTesting;
import dev.sigstore.VerificationOptions.CTLogOptions;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.certificates.transparency.CTLogInfo;
import dev.sigstore.encryption.certificates.transparency.CTVerificationResult;
import dev.sigstore.encryption.certificates.transparency.CTVerifier;
import dev.sigstore.trustroot.CertificateAuthority;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/** Verifier for fulcio generated signing certificates */
public class FulcioVerifier {
  private static final String BASIC_CONSTRAINTS_OID = Extension.basicConstraints.getId();
  private static final String KEY_USAGE_OID = Extension.keyUsage.getId();
  private static final String EXTENDED_KEY_USAGE_OID = Extension.extendedKeyUsage.getId();
  private static final String CODE_SIGNING_EKU_OID = KeyPurposeId.id_kp_codeSigning.getId();
  private static final int DIGITAL_SIGNATURE_KEY_USAGE_INDEX = 0;

  private final List<CertificateAuthority> cas;
  private final List<TransparencyLog> ctLogs;
  private final CTVerifier ctVerifier;

  public static FulcioVerifier newFulcioVerifier(SigstoreTrustedRoot trustRoot)
      throws InvalidAlgorithmParameterException,
          CertificateException,
          InvalidKeySpecException,
          NoSuchAlgorithmException {
    return newFulcioVerifier(trustRoot.getCAs(), trustRoot.getCTLogs());
  }

  public static FulcioVerifier newFulcioVerifier(
      List<CertificateAuthority> cas, List<TransparencyLog> ctLogs)
      throws InvalidKeySpecException,
          NoSuchAlgorithmException,
          InvalidAlgorithmParameterException,
          CertificateException {
    List<CTLogInfo> logs = new ArrayList<>();
    for (var ctLog : ctLogs) {
      logs.add(
          new CTLogInfo(
              ctLog.getPublicKey().toJavaPublicKey(), "CT Log", ctLog.getBaseUrl().toString()));
    }
    var verifier =
        new CTVerifier(
            logId ->
                logs.stream()
                    .filter(ctLogInfo -> Arrays.equals(ctLogInfo.getID(), logId))
                    .findFirst()
                    .orElse(null));

    // check to see if we can use all fulcio roots (this is a bit eager)
    for (var ca : cas) {
      ca.asTrustAnchor();
    }

    return new FulcioVerifier(cas, ctLogs, verifier);
  }

  private FulcioVerifier(
      List<CertificateAuthority> cas, List<TransparencyLog> ctLogs, CTVerifier ctVerifier) {
    this.cas = cas;
    this.ctLogs = ctLogs;
    this.ctVerifier = ctVerifier;
  }

  @VisibleForTesting
  void verifySct(CertPath fullCertPath, CTLogOptions ctLogOptions)
      throws FulcioVerificationException {
    if (ctLogs.isEmpty()) {
      // Only when there are no CT Logs (private deployment) we can skip SCT verification
      if (!ctLogOptions.isEnabled()) {
        return;
      }
      throw new FulcioVerificationException("No ct logs were provided to verifier");
    }

    if (Certificates.getEmbeddedSCTs(Certificates.getLeaf(fullCertPath)).isPresent()) {
      verifyEmbeddedScts(fullCertPath);
    } else {
      throw new FulcioVerificationException("No valid SCTs were found during verification");
    }
  }

  private void verifyEmbeddedScts(CertPath certPath) throws FulcioVerificationException {
    @SuppressWarnings("unchecked")
    var certs = (List<X509Certificate>) certPath.getCertificates();
    CTVerificationResult result;
    try {
      result = ctVerifier.verifySignedCertificateTimestamps(certs, null, null);
    } catch (CertificateEncodingException cee) {
      throw new FulcioVerificationException(
          "Certificates could not be parsed during SCT verification");
    }

    // these are technically valid, but we have the additional constraint of sigstore's trustroot
    // providing a validity period for logs, so make sure all SCTs were signed by a log during
    // that log's validity period
    for (var validSct : result.getValidSCTs()) {
      var sct = validSct.sct;

      var logId = sct.getLogID();
      var entryTime = Instant.ofEpochMilli(sct.getTimestamp());

      var ctLog = TransparencyLog.find(ctLogs, logId, entryTime);
      if (ctLog.isPresent()) {
        // TODO: currently we only require one valid SCT, but maybe this should be configurable?
        // found at least one valid sct with a matching valid log
        return;
      }
    }
    throw new FulcioVerificationException(
        "No valid SCTs were found, all("
            + (result.getValidSCTs().size() + result.getInvalidSCTs().size())
            + ") SCTs were invalid");
  }

  /**
   * Verify that the leaf certificate conforms to the Sigstore X.509 leaf profile, that the cert
   * chain is valid and chains up to the trust anchor (fulcio public key) configured in this
   * validator, and that the leaf certificate contains at least one valid SCT.
   *
   * @param signingCertificate containing a certificate chain, this chain should not contain any
   *     trusted root or trusted intermediates
   * @throws FulcioVerificationException if verification fails for any reason
   */
  public void verifySigningCertificate(CertPath signingCertificate)
      throws FulcioVerificationException, IOException {
    verifySigningCertificate(signingCertificate, CTLogOptions.builder().isEnabled(true).build());
  }

  /**
   * Verify a signing certificate against the Sigstore X.509 leaf profile and trust anchors,
   * applying the given certificate-transparency policy (see {@link #verifySct(CertPath,
   * CTLogOptions)}).
   */
  public void verifySigningCertificate(CertPath signingCertificate, CTLogOptions ctLogOptions)
      throws FulcioVerificationException, IOException {
    verifyLeafCertificate(Certificates.getLeaf(signingCertificate));
    CertPath fullCertPath = validateCertPath(signingCertificate);
    verifyIntermediateCertificates(fullCertPath);
    verifySct(fullCertPath, ctLogOptions);
  }

  /**
   * Verify that the leaf certificate conforms to the Sigstore X.509 leaf profile: X.509 v3, not a
   * CA (critical BasicConstraints if present), critical KeyUsage with only digitalSignature, and
   * non-critical ExtendedKeyUsage with only codeSigning. PKIX path validation does not check these
   * constraints for the end-entity certificate.
   */
  private static void verifyLeafCertificate(X509Certificate leaf)
      throws FulcioVerificationException {
    if (leaf.getVersion() != 3) {
      throw new FulcioVerificationException(
          "Signing certificate must be X.509 v3, but was v" + leaf.getVersion());
    }

    // Check BasicConstraints criticality before getBasicConstraints(): JDK X509CertImpl returns -1
    // for unparseable non-critical BasicConstraints, so this check is what rejects malformed ones.
    var nonCriticalOids = leaf.getNonCriticalExtensionOIDs();
    if (nonCriticalOids != null && nonCriticalOids.contains(BASIC_CONSTRAINTS_OID)) {
      throw new FulcioVerificationException(
          "Signing certificate BasicConstraints extension must be marked critical");
    }
    if (leaf.getBasicConstraints() != -1) {
      throw new FulcioVerificationException("Signing certificate must not be a CA");
    }

    if (nonCriticalOids != null && nonCriticalOids.contains(KEY_USAGE_OID)) {
      throw new FulcioVerificationException(
          "Signing certificate KeyUsage extension must be marked critical");
    }
    var keyUsage = leaf.getKeyUsage();
    if (keyUsage == null) {
      throw new FulcioVerificationException("Signing certificate is missing KeyUsage extension");
    }
    if (keyUsage.length <= DIGITAL_SIGNATURE_KEY_USAGE_INDEX
        || !keyUsage[DIGITAL_SIGNATURE_KEY_USAGE_INDEX]) {
      throw new FulcioVerificationException(
          "Signing certificate key usage does not include digitalSignature");
    }
    for (int i = 0; i < keyUsage.length; i++) {
      if (i != DIGITAL_SIGNATURE_KEY_USAGE_INDEX && keyUsage[i]) {
        throw new FulcioVerificationException(
            "Signing certificate key usage must only include digitalSignature");
      }
    }

    var criticalOids = leaf.getCriticalExtensionOIDs();
    if (criticalOids != null && criticalOids.contains(EXTENDED_KEY_USAGE_OID)) {
      throw new FulcioVerificationException(
          "Signing certificate ExtendedKeyUsage extension must not be marked critical");
    }
    var extendedKeyUsage = getExtendedKeyUsage(leaf, "signing certificate");
    if (extendedKeyUsage == null) {
      throw new FulcioVerificationException(
          "Signing certificate is missing ExtendedKeyUsage extension");
    }
    if (!extendedKeyUsage.contains(CODE_SIGNING_EKU_OID)) {
      throw new FulcioVerificationException(
          "Signing certificate extended key usage does not include codeSigning");
    }
    if (extendedKeyUsage.size() != 1) {
      throw new FulcioVerificationException(
          "Signing certificate extended key usage must only include codeSigning");
    }
  }

  /**
   * Verify that any intermediate CA certificates in the validated chain (excluding the leaf and
   * trust anchor) that specify an ExtendedKeyUsage extension include {@code codeSigning}.
   */
  private static void verifyIntermediateCertificates(CertPath fullCertPath)
      throws FulcioVerificationException {
    var certs = fullCertPath.getCertificates();
    for (int i = 1; i < certs.size() - 1; i++) {
      var intermediate = (X509Certificate) certs.get(i);
      var extendedKeyUsage = getExtendedKeyUsage(intermediate, "intermediate certificate");
      if (extendedKeyUsage != null && !extendedKeyUsage.contains(CODE_SIGNING_EKU_OID)) {
        throw new FulcioVerificationException(
            "Intermediate certificate extended key usage does not include codeSigning");
      }
    }
  }

  private static List<String> getExtendedKeyUsage(X509Certificate cert, String certType)
      throws FulcioVerificationException {
    List<String> extendedKeyUsage;
    try {
      extendedKeyUsage = cert.getExtendedKeyUsage();
    } catch (CertificateParsingException e) {
      throw new FulcioVerificationException(
          "Could not parse " + certType + " ExtendedKeyUsage extension", e);
    }
    // JDK <= 17 X509CertImpl returns null (instead of throwing) for unparseable non-critical EKU.
    if (extendedKeyUsage == null && cert.getExtensionValue(EXTENDED_KEY_USAGE_OID) != null) {
      throw new FulcioVerificationException(
          "Could not parse " + certType + " ExtendedKeyUsage extension");
    }
    return extendedKeyUsage;
  }

  public CertPath trimTrustedParent(CertPath signingCertificate)
      throws FulcioVerificationException, CertificateException {
    for (var ca : cas) {
      if (Certificates.containsParent(signingCertificate, ca.getCertPath())) {
        return Certificates.trimParent(signingCertificate, ca.getCertPath());
      }
    }
    throw new FulcioVerificationException("Certificate does not chain to trusted roots");
  }

  /**
   * Find a valid cert path that chains back up to the trusted root certs and reconstruct a
   * certificate path combining the provided un-trusted certs and a known set of trusted and
   * intermediate certs. If a full certificate is provided with a self signed root, this should
   * attempt to match the root/intermediate with a trusted chain.
   */
  CertPath validateCertPath(CertPath signingCertificate) throws FulcioVerificationException {
    CertPathValidator cpv;
    try {
      cpv = CertPathValidator.getInstance("PKIX");
    } catch (NoSuchAlgorithmException e) {
      //
      throw new RuntimeException(
          "No PKIX CertPathValidator, we probably shouldn't be here, but this seems to be a system"
              + " library error not a program control flow issue",
          e);
    }

    var leaf = Certificates.getLeaf(signingCertificate);
    var validCAs = CertificateAuthority.find(cas, leaf.getNotBefore().toInstant());

    if (validCAs.size() == 0) {
      throw new FulcioVerificationException(
          "No valid Certificate Authorities found when validating certificate");
    }

    Map<String, String> caVerificationFailure = new LinkedHashMap<>();

    for (var ca : validCAs) {
      PKIXParameters pkixParams;
      try {
        pkixParams = new PKIXParameters(Collections.singleton(ca.asTrustAnchor()));
      } catch (InvalidAlgorithmParameterException | CertificateException e) {
        throw new RuntimeException(
            "Can't create PKIX parameters for fulcioRoot. This should have been checked when"
                + " generating a verifier instance",
            e);
      }
      pkixParams.setRevocationEnabled(false);

      // these certs are only valid for 15 minutes, so find a time in the validity period
      @SuppressWarnings("JavaUtilDate")
      Date dateInValidityPeriod =
          new Date(Certificates.getLeaf(signingCertificate).getNotBefore().getTime());
      pkixParams.setDate(dateInValidityPeriod);

      CertPath fullCertPath;
      try {
        if (Certificates.isSelfSigned(signingCertificate)) {
          if (Certificates.containsParent(signingCertificate, ca.getCertPath())) {
            fullCertPath = signingCertificate;
          } else {
            // verification failed because we didn't match to a trusted root
            caVerificationFailure.put(
                ca.getUri().toString(), "Trusted root in chain does not match");
            continue;
          }
        } else {
          // build a cert chain with the root-chain in question and the provided signing certificate
          fullCertPath = Certificates.append(ca.getCertPath(), signingCertificate);
        }

        // a result is returned here, but we ignore it
        cpv.validate(fullCertPath, pkixParams);
      } catch (CertPathValidatorException
          | InvalidAlgorithmParameterException
          | CertificateException ve) {
        caVerificationFailure.put(ca.getUri().toString(), ve.getMessage());
        // verification failed
        continue;
      }
      return fullCertPath;
      // verification passed so just end this method
    }
    String errors =
        caVerificationFailure.entrySet().stream()
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .collect(Collectors.joining("\n"));
    throw new FulcioVerificationException("Certificate was not verifiable against CAs\n" + errors);
  }
}
