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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.conscrypt.ct.CTLogInfo;
import org.conscrypt.ct.CertificateEntry;
import org.conscrypt.ct.SignedCertificateTimestamp;
import org.conscrypt.ct.VerifiedSCT;

public class FulcioValidator {
  @Nullable private final CTLogInfo ctLogInfo;
  private final TrustAnchor fulcioRoot;

  public static FulcioValidator newFulcioValidator(
      byte[] fulcioRoot, byte @Nullable [] ctfePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException,
          InvalidAlgorithmParameterException {

    CTLogInfo ctLogInfo = null;
    if (ctfePublicKey != null) {
      PublicKey ctfePublicKeyObj = Keys.parsePublicKey(ctfePublicKey);
      ctLogInfo = new CTLogInfo(ctfePublicKeyObj, "fulcio ct log", "unused-url");
    }

    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate fulcioRootObj =
        (X509Certificate)
            certificateFactory.generateCertificate(new ByteArrayInputStream(fulcioRoot));

    TrustAnchor fulcioRootTrustAnchor = new TrustAnchor(fulcioRootObj, null);
    // this should throw an InvalidAlgorithmException a bit earlier that would otherwise be
    // encountered
    // in validateCertPath
    new PKIXParameters(Collections.singleton(fulcioRootTrustAnchor));

    return new FulcioValidator(ctLogInfo, fulcioRootTrustAnchor);
  }

  private FulcioValidator(@Nullable CTLogInfo ctLogInfo, TrustAnchor fulcioRoot) {
    this.ctLogInfo = ctLogInfo;
    this.fulcioRoot = fulcioRoot;
  }

  public void validateSct(SigningCertificate sc) throws FulcioValidationException {

    SignedCertificateTimestamp sct =
        sc.getSct()
            .orElseThrow(() -> new FulcioValidationException("No SCT was found to validate"));
    if (ctLogInfo == null) {
      throw new FulcioValidationException("No ct-log public key was provided to validator");
    }

    // leaf certificate are guaranteed to be X509Certificates if they were built via
    // a client request.
    if (!(sc.getLeafCertificate() instanceof X509Certificate)) {
      throw new RuntimeException(
          "Encountered non X509 Certificate when validating SCT. Leaf certificate is "
              + sc.getLeafCertificate().getClass());
    }
    CertificateEntry ce;

    try {
      ce = CertificateEntry.createForX509Certificate((X509Certificate) sc.getLeafCertificate());
    } catch (CertificateEncodingException cee) {
      throw new FulcioValidationException("Leaf certificate could not be parsed", cee);
    }

    VerifiedSCT.Status status = ctLogInfo.verifySingleSCT(sct, ce);
    if (status != VerifiedSCT.Status.VALID) {
      throw new FulcioValidationException("SCT could not be verified because " + status.toString());
    }
  }

  public void validateCertChain(SigningCertificate sc) throws FulcioValidationException {
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
          "Can't create PKIX parameters for fulcioRoot. This should have been checked when generating a validator instance",
          e);
    }
    pkixParams.setRevocationEnabled(false);

    // these certs are only valid for 15 minutes, so find a time in the validity period
    Date dateInValidityPeriod =
        new Date(((X509Certificate) sc.getLeafCertificate()).getNotBefore().getTime());
    pkixParams.setDate(dateInValidityPeriod);

    try {
      // a result is returned here, but I don't know what to do with it yet
      cpv.validate(sc.getCertPath(), pkixParams);
    } catch (CertPathValidatorException | InvalidAlgorithmParameterException ve) {
      throw new FulcioValidationException(ve);
    }
  }
}
