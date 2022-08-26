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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CTVerifier {
  private final CTLogStore store;

  public CTVerifier(CTLogStore store) {
    this.store = store;
  }

  /**
   * Verify a certificate chain for transparency. Signed timestamps are extracted from the leaf
   * certificate and verified against the list of known logs.
   *
   * @throws IllegalArgumentException if the chain is empty
   */
  public CTVerificationResult verifySignedCertificateTimestamps(
      List<X509Certificate> chain, byte[] tlsData, byte[] ocspData)
      throws CertificateEncodingException {
    if (chain.size() == 0) {
      throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
    }

    X509Certificate leaf = chain.get(0);

    CTVerificationResult result = new CTVerificationResult();
    List<SignedCertificateTimestamp> embeddedScts = getSCTsFromX509Extension(leaf);
    verifyEmbeddedSCTs(embeddedScts, chain, result);
    return result;
  }

  /**
   * Verify a list of SCTs which were embedded from an X509 certificate. The result of the
   * verification for each sct is added to {@code result}.
   */
  private void verifyEmbeddedSCTs(
      List<SignedCertificateTimestamp> scts,
      List<X509Certificate> chain,
      CTVerificationResult result) {
    // Avoid creating the cert entry if we don't need it
    if (scts.isEmpty()) {
      return;
    }

    CertificateEntry precertEntry = null;
    if (chain.size() >= 2) {
      X509Certificate leaf = chain.get(0);
      X509Certificate issuer = chain.get(1);

      try {
        precertEntry = CertificateEntry.createForPrecertificate(leaf, issuer);
      } catch (CertificateException e) {
        // Leave precertEntry as null, we handle it just below
      }
    }

    if (precertEntry == null) {
      markSCTsAsInvalid(scts, result);
      return;
    }

    for (SignedCertificateTimestamp sct : scts) {
      VerifiedSCT.Status status = verifySingleSCT(sct, precertEntry);
      result.add(new VerifiedSCT(sct, status));
    }
  }

  /** Verify a single SCT for the given Certificate Entry */
  public VerifiedSCT.Status verifySingleSCT(
      SignedCertificateTimestamp sct, CertificateEntry certEntry) {
    CTLogInfo log = store.getKnownLog(sct.getLogID());
    if (log == null) {
      return VerifiedSCT.Status.UNKNOWN_LOG;
    }

    return log.verifySingleSCT(sct, certEntry);
  }

  /** Add every SCT in {@code scts} to {@code result} with INVALID_SCT as status */
  private void markSCTsAsInvalid(
      List<SignedCertificateTimestamp> scts, CTVerificationResult result) {
    for (SignedCertificateTimestamp sct : scts) {
      result.add(new VerifiedSCT(sct, VerifiedSCT.Status.INVALID_SCT));
    }
  }

  /**
   * Parse an encoded SignedCertificateTimestampList into a list of SignedCertificateTimestamp
   * instances, as described by RFC6962. Individual SCTs which fail to be parsed are skipped. If the
   * data is null, or the encompassing list fails to be parsed, an empty list is returned.
   *
   * @param origin used to create the SignedCertificateTimestamp instances.
   */
  @SuppressWarnings("MixedMutabilityReturnType")
  private static List<SignedCertificateTimestamp> getSCTsFromSCTList(
      byte[] data, SignedCertificateTimestamp.Origin origin) {
    if (data == null) {
      return Collections.emptyList();
    }

    byte[][] sctList;
    try {
      sctList =
          Serialization.readList(
              data, CTConstants.SCT_LIST_LENGTH_BYTES, CTConstants.SERIALIZED_SCT_LENGTH_BYTES);
    } catch (SerializationException e) {
      return Collections.emptyList();
    }

    List<SignedCertificateTimestamp> scts = new ArrayList<>();
    for (byte[] encodedSCT : sctList) {
      try {
        SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(encodedSCT, origin);
        scts.add(sct);
      } catch (SerializationException e) {
        // Ignore errors
      }
    }

    return scts;
  }

  /**
   * Extract a list of SignedCertificateTimestamp embedded in an X509 certificate.
   *
   * <p>If the certificate does not contain any SCT extension, or the encompassing encoded list
   * fails to be parsed, an empty list is returned. Individual SCTs which fail to be parsed are
   * ignored.
   */
  private List<SignedCertificateTimestamp> getSCTsFromX509Extension(X509Certificate leaf) {
    byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
    if (extData == null) {
      return Collections.emptyList();
    }

    try {
      return getSCTsFromSCTList(
          Serialization.readDEROctetString(Serialization.readDEROctetString(extData)),
          SignedCertificateTimestamp.Origin.EMBEDDED);
    } catch (SerializationException e) {
      return Collections.emptyList();
    }
  }
}
