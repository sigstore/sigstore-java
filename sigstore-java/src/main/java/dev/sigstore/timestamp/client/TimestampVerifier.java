/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.timestamp.client;

import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.trustroot.CertificateAuthority;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

public class TimestampVerifier {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final List<CertificateAuthority> tsas;

  public static TimestampVerifier newTimestampVerifier(SigstoreTrustedRoot trustedRoot)
      throws InvalidAlgorithmParameterException,
          CertificateException,
          InvalidKeySpecException,
          NoSuchAlgorithmException {
    return newTimestampVerifier(trustedRoot.getTSAs());
  }

  public static TimestampVerifier newTimestampVerifier(List<CertificateAuthority> tsas)
      throws InvalidKeySpecException,
          NoSuchAlgorithmException,
          InvalidAlgorithmParameterException,
          CertificateException {
    // check to see if we can use all TSAs (this is a bit eager)
    for (var tsa : tsas) {
      tsa.asTrustAnchor();
    }

    return new TimestampVerifier(tsas);
  }

  private TimestampVerifier(List<CertificateAuthority> tsas) {
    this.tsas = tsas;
  }

  /**
   * Verifies a timestamp response against the configured trusted Timestamp Authorities (TSAs).
   *
   * @param tsResp The timestamp response object containing the raw bytes of the RFC 3161
   *     TimeStampResponse.
   * @throws TimestampVerificationException if any verification step fails (e.g., no token,
   *     certificate path validation failure, signature validation failure).
   */
  public void verify(TimestampResponse tsResp) throws TimestampVerificationException {
    // Parse the timestamp response
    TimeStampResponse bcTsResp;
    try {
      bcTsResp = new TimeStampResponse(tsResp.getEncoded());
    } catch (TSPException | IOException e) {
      throw new TimestampVerificationException("Failed to parse TimeStampResponse", e);
    }

    // Get the timestamp token
    var tsToken = bcTsResp.getTimeStampToken();
    if (tsToken == null) {
      throw new TimestampVerificationException("No TimeStampToken found in response");
    }

    Map<String, String> tsaVerificationFailure = new LinkedHashMap<>();

    // Check if the token contains embedded certificates
    var tsCertStore = tsToken.getCertificates();
    var hasEmbeddedCerts = false;
    if (tsCertStore != null) {
      hasEmbeddedCerts = !tsCertStore.getMatches(null).isEmpty();
    }

    // Determine the trusted TSA that signed this token
    CertificateAuthority tsa;
    if (hasEmbeddedCerts) {
      tsa = findVerifyingTsaFromEmbeddedCerts(tsToken);
    } else {
      tsa = findVerifyingTsaByLeafSignature(tsToken);
    }

    // Validate the certificate chain of the TSA
    try {
      validateTsaChain(tsa, tsToken.getTimeStampInfo().getGenTime());
    } catch (TimestampException
        | NoSuchProviderException
        | InvalidAlgorithmParameterException
        | CertPathValidatorException e) {
      throw new TimestampVerificationException("Failed to validate TSA chain", e);
    }

    // Check if the generation time of the timestamp falls within the validity period of the TSA
    if (!tsa.getValidFor().contains(tsToken.getTimeStampInfo().getGenTime().toInstant())) {
      tsaVerificationFailure.put(
          tsa.getUri().toString(),
          "Timestamp generation time is not within TSA's validity period.");
    } else {
      return;
    }

    String errors =
        tsaVerificationFailure.entrySet().stream()
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .collect(Collectors.joining("\n"));
    throw new TimestampVerificationException(
        "Certificate was not verifiable against TSAs\n" + errors);
  }

  /** Validates the signature of the TimeStampToken using the provided signing certificate. */
  private void validateTokenSignature(TimeStampToken token, X509Certificate signingCert)
      throws TimestampVerificationException {
    try {
      var verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
      var verifier = verifierBuilder.setProvider("BC").build(signingCert);
      token.validate(verifier);
    } catch (OperatorCreationException oce) {
      throw new TimestampVerificationException("Failed to build SignerInformationVerifier", oce);
    } catch (TSPException tspe) {
      throw new TimestampVerificationException("Failed to validate TimeStampToken", tspe);
    }
  }

  /** Validates that the provided TSA's certificate chain is self-consistent. */
  void validateTsaChain(CertificateAuthority tsa, Date tsDate)
      throws TimestampException,
          NoSuchProviderException,
          CertPathValidatorException,
          InvalidAlgorithmParameterException { // Accept validation date
    CertPathValidator cpv;
    try {
      cpv = CertPathValidator.getInstance("PKIX");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(
          "No PKIX CertPathValidator, we probably shouldn't be here, but this seems to be a system library error not a program control flow issue",
          e);
    }

    PKIXParameters pkixParams;
    try {
      pkixParams = new PKIXParameters(Collections.singleton(tsa.asTrustAnchor()));
    } catch (InvalidAlgorithmParameterException | CertificateException e) {
      throw new RuntimeException(
          "Can't create PKIX parameters for the TSA. This should have been checked when generating a verifier instance",
          e);
    }
    pkixParams.setRevocationEnabled(false);
    pkixParams.setDate(tsDate);

    cpv.validate(tsa.getCertPath(), pkixParams);
  }

  /**
   * Finds the TSA that verifies the provided timestamp token by validating its signature using the
   * certificate chain embedded within the token and matching the leaf to a known TSA.
   */
  CertificateAuthority findVerifyingTsaFromEmbeddedCerts(TimeStampToken tsToken)
      throws TimestampVerificationException {
    var tsCertStore = tsToken.getCertificates();
    List<Certificate> tsCerts = new ArrayList<>();

    // Get list of X509Certificates from token
    var tsCertHolders = tsCertStore.getMatches(null);
    for (var tsCertHolder : tsCertHolders) {
      var converter = new JcaX509CertificateConverter().setProvider("BC");
      try {
        var cert = converter.getCertificate(tsCertHolder);
        tsCerts.add(cert);
      } catch (CertificateException ce) {
        throw new TimestampVerificationException(
            "Unable to convert certificate to X509Certificate", ce);
      }
    }

    // Convert list of X509Certificates to certPath
    CertPath tsCertPath;
    try {
      tsCertPath = Certificates.toCertPath(tsCerts);
    } catch (CertificateException ce) {
      throw new TimestampVerificationException("Cannot convert certificates to CertPath", ce);
    }

    Map<String, String> tsaVerificationFailure = new LinkedHashMap<>();

    for (var tsa : tsas) {
      var tsaChain = tsa.getCertPath();
      // Check if the leaf certificate from the token matches the leaf of the trusted TSA chain
      if (Certificates.getLeaf(tsCertPath).equals(Certificates.getLeaf(tsaChain))) {
        // If the leaves match, proceed to validate the signature using the leaf
        validateTokenSignature(tsToken, Certificates.getLeaf(tsCertPath));
        return tsa;
      } else {
        tsaVerificationFailure.put(
            tsa.getUri().toString(),
            "Embedded leaf certificate does not match this trusted TSA's leaf.");
      }
    }

    String errors =
        tsaVerificationFailure.entrySet().stream()
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .collect(Collectors.joining("\n"));
    throw new TimestampVerificationException(
        "Certificates in token were not verifiable against TSAs\n" + errors);
  }

  /**
   * Finds the TSA that verifies the provided timestamp token by validating its signature against
   * the leaf certificates of known trusted TSAs.
   */
  CertificateAuthority findVerifyingTsaByLeafSignature(TimeStampToken tsToken)
      throws TimestampVerificationException {
    Map<String, String> tsaVerificationFailure = new LinkedHashMap<>();

    for (var tsa : tsas) {
      var tsaChain = tsa.getCertPath();
      var tsaLeaf = Certificates.getLeaf(tsaChain);

      // Check if the tsToken's signature matches that TSA's leaf certificate's public key
      try {
        validateTokenSignature(tsToken, tsaLeaf);
        return tsa;
      } catch (TimestampVerificationException tsve) {
        tsaVerificationFailure.put(tsa.getUri().toString(), tsve.getMessage());
      }
    }

    String errors =
        tsaVerificationFailure.entrySet().stream()
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .collect(Collectors.joining("\n"));
    throw new TimestampVerificationException(
        "Certificates in token were not verifiable against TSAs\n" + errors);
  }
}
