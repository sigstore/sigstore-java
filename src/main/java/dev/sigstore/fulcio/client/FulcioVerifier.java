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

import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.certificates.transparency.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import org.checkerframework.checker.nullness.qual.Nullable;

/** Verifier for fulcio {@link dev.sigstore.fulcio.client.SigningCertificate}. */
public class FulcioVerifier {
  @Nullable private final CTVerifier ctVerifier;
  private final TrustAnchor fulcioRoot;

  /**
   * Instantiate a new verifier.
   *
   * @param fulcioRoot fulcio's root certificate
   * @param ctfePublicKey fulcio's certificate transparency log's public key
   */
  public static FulcioVerifier newFulcioVerifier(byte[] fulcioRoot, byte @Nullable [] ctfePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException,
          InvalidAlgorithmParameterException {

    PublicKey ctfePublicKeyObj = null;
    if (ctfePublicKey != null) {
      ctfePublicKeyObj = Keys.parsePublicKey(ctfePublicKey);
    }

    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate fulcioRootObj =
        (X509Certificate)
            certificateFactory.generateCertificate(new ByteArrayInputStream(fulcioRoot));

    TrustAnchor fulcioRootTrustAnchor = new TrustAnchor(fulcioRootObj, null);
    // this should throw an InvalidAlgorithmException a bit earlier that would otherwise be
    // encountered in verifyCertPath
    new PKIXParameters(Collections.singleton(fulcioRootTrustAnchor));

    return new FulcioVerifier(fulcioRootTrustAnchor, ctfePublicKeyObj);
  }

  private FulcioVerifier(TrustAnchor fulcioRoot, @Nullable PublicKey ctfePublicKey) {
    this.fulcioRoot = fulcioRoot;
    if (ctfePublicKey != null) {
      var ctLogInfo = new CTLogInfo(ctfePublicKey, "fulcio ct log", "unused-url");
      this.ctVerifier =
          new CTVerifier(logId -> Arrays.equals(logId, ctLogInfo.getID()) ? ctLogInfo : null);
    } else {
      ctVerifier = null;
    }
  }

  /**
   * Verify that an SCT associated with a Singing Certificate is valid and signed by the configured
   * CT-log public key.
   *
   * @param signingCertificate containing the SCT metadata to verify
   * @throws FulcioVerificationException if verification fails for any reason
   */
  public void verifySct(SigningCertificate signingCertificate) throws FulcioVerificationException {
    if (ctVerifier == null) {
      throw new FulcioVerificationException("No ct-log public key was provided to verifier");
    }

    if (signingCertificate.getDetachedSct().isPresent()) {
      CertificateEntry ce;
      try {
        ce = CertificateEntry.createForX509Certificate(signingCertificate.getLeafCertificate());
      } catch (CertificateEncodingException cee) {
        throw new FulcioVerificationException("Leaf certificate could not be parsed", cee);
      }

      var status = ctVerifier.verifySingleSCT(signingCertificate.getDetachedSct().get(), ce);
      if (status != VerifiedSCT.Status.VALID) {
        throw new FulcioVerificationException(
            "SCT could not be verified because " + status.toString());
      }
    } else if (signingCertificate.hasEmbeddedSct()) {
      var certs = signingCertificate.getCertificates();
      CTVerificationResult result;
      try {
        // even though we're sending the whole chain, this method only checks SCTs on the leaf cert
        result = ctVerifier.verifySignedCertificateTimestamps(certs, null, null);
      } catch (CertificateEncodingException cee) {
        throw new FulcioVerificationException(
            "Certificates could not be parsed during sct verification");
      }
      int valid = result.getValidSCTs().size();
      int invalid = result.getInvalidSCTs().size();
      if (valid == 0 || invalid != 0) {
        throw new FulcioVerificationException(
            "Expecting at least one valid sct, but found "
                + valid
                + " valid and "
                + invalid
                + " invalid scts");
      }
    } else {
      throw new FulcioVerificationException("No detached or embedded SCTs were found to verify");
    }
  }

  /**
   * Verify that a cert chain is valid and chains up to the trust anchor (fulcio public key)
   * configured in this validator.
   *
   * @param signingCertificate containing the certificate chain
   * @throws FulcioVerificationException if verification fails for any reason
   */
  public void verifyCertChain(SigningCertificate signingCertificate)
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

    PKIXParameters pkixParams;
    try {
      pkixParams = new PKIXParameters(Collections.singleton(fulcioRoot));
    } catch (InvalidAlgorithmParameterException e) {
      throw new RuntimeException(
          "Can't create PKIX parameters for fulcioRoot. This should have been checked when generating a verifier instance",
          e);
    }
    pkixParams.setRevocationEnabled(false);

    // these certs are only valid for 15 minutes, so find a time in the validity period
    Date dateInValidityPeriod =
        new Date(signingCertificate.getLeafCertificate().getNotBefore().getTime());
    pkixParams.setDate(dateInValidityPeriod);

    try {
      // a result is returned here, but I don't know what to do with it yet
      cpv.validate(signingCertificate.getCertPath(), pkixParams);
    } catch (CertPathValidatorException | InvalidAlgorithmParameterException ve) {
      throw new FulcioVerificationException(ve);
    }
  }
}
