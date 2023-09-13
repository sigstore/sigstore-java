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
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.certificates.transparency.CTLogInfo;
import dev.sigstore.encryption.certificates.transparency.CTVerificationResult;
import dev.sigstore.encryption.certificates.transparency.CTVerifier;
import dev.sigstore.trustroot.CertificateAuthorities;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLogs;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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

/** Verifier for fulcio {@link SigningCertificate}. */
public class FulcioVerifier2 {
  private final CertificateAuthorities cas;
  private final TransparencyLogs ctLogs;
  private final CTVerifier ctVerifier;

  public static FulcioVerifier2 newFulcioVerifier(SigstoreTrustedRoot trustRoot)
      throws InvalidAlgorithmParameterException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    return newFulcioVerifier(trustRoot.getCAs(), trustRoot.getCTLogs());
  }

  public static FulcioVerifier2 newFulcioVerifier(
      CertificateAuthorities cas, TransparencyLogs ctLogs)
      throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          CertificateException {
    List<CTLogInfo> logs = new ArrayList<>();
    for (var ctLog : ctLogs.all()) {
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
    for (var ca : cas.all()) {
      ca.asTrustAnchor();
    }

    return new FulcioVerifier2(cas, ctLogs, verifier);
  }

  private FulcioVerifier2(
      CertificateAuthorities cas, TransparencyLogs ctLogs, CTVerifier ctVerifier) {
    this.cas = cas;
    this.ctLogs = ctLogs;
    this.ctVerifier = ctVerifier;
  }

  @VisibleForTesting
  void verifySct(SigningCertificate signingCertificate, CertPath rebuiltCert)
      throws FulcioVerificationException {
    if (ctLogs.size() == 0) {
      throw new FulcioVerificationException("No ct logs were provided to verifier");
    }

    if (signingCertificate.getDetachedSct().isPresent()) {
      throw new FulcioVerificationException(
          "Detached SCTs are not supported for validating certificates");
    } else if (signingCertificate.getEmbeddedSct().isPresent()) {
      verifyEmbeddedScts(rebuiltCert);
    } else {
      throw new FulcioVerificationException("No valid SCTs were found during verification");
    }
  }

  private void verifyEmbeddedScts(CertPath rebuiltCert) throws FulcioVerificationException {
    @SuppressWarnings("unchecked")
    var certs = (List<X509Certificate>) rebuiltCert.getCertificates();
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

      var ctLog = ctLogs.find(logId, entryTime);
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
   * Verify that a cert chain is valid and chains up to the trust anchor (fulcio public key)
   * configured in this validator. Also verify that the leaf certificate contains at least one valid
   * SCT
   *
   * @param signingCertificate containing the certificate chain
   * @throws FulcioVerificationException if verification fails for any reason
   */
  public void verifySigningCertificate(SigningCertificate signingCertificate)
      throws FulcioVerificationException, IOException {
    CertPath reconstructedCert = reconstructValidCertPath(signingCertificate);
    verifySct(signingCertificate, reconstructedCert);
  }

  /**
   * Find a valid cert path that chains back up to the trusted root certs and reconstruct a
   * certificate path combining the provided un-trusted certs and a known set of trusted and
   * intermediate certs.
   */
  CertPath reconstructValidCertPath(SigningCertificate signingCertificate)
      throws FulcioVerificationException {
    CertPathValidator cpv;
    try {
      cpv = CertPathValidator.getInstance("PKIX");
    } catch (NoSuchAlgorithmException e) {
      //
      throw new RuntimeException(
          "No PKIX CertPathValidator, we probably shouldn't be here, but this seems to be a system library error not a program control flow issue",
          e);
    }

    var leaf = signingCertificate.getLeafCertificate();
    var validCAs = cas.find(leaf.getNotBefore().toInstant());

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
            "Can't create PKIX parameters for fulcioRoot. This should have been checked when generating a verifier instance",
            e);
      }
      pkixParams.setRevocationEnabled(false);

      // these certs are only valid for 15 minutes, so find a time in the validity period
      @SuppressWarnings("JavaUtilDate")
      Date dateInValidityPeriod =
          new Date(signingCertificate.getLeafCertificate().getNotBefore().getTime());
      pkixParams.setDate(dateInValidityPeriod);

      CertPath rebuiltCert;
      try {
        // build a cert chain with the root-chain in question and the provided leaf
        rebuiltCert =
            Certificates.appendCertPath(ca.getCertPath(), signingCertificate.getLeafCertificate());

        // a result is returned here, but we ignore it
        cpv.validate(rebuiltCert, pkixParams);
      } catch (CertPathValidatorException
          | InvalidAlgorithmParameterException
          | CertificateException ve) {
        caVerificationFailure.put(ca.getUri().toString(), ve.getMessage());
        // verification failed
        continue;
      }
      return rebuiltCert;
      // verification passed so just end this method
    }
    String errors =
        caVerificationFailure.entrySet().stream()
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .collect(Collectors.joining("\n"));
    throw new FulcioVerificationException("Certificate was not verifiable against CAs\n" + errors);
  }
}
