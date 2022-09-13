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
package dev.sigstore;

import com.google.api.client.util.Preconditions;
import com.google.common.io.Resources;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.fulcio.client.FulcioVerificationException;
import dev.sigstore.fulcio.client.FulcioVerifier;
import dev.sigstore.fulcio.client.SigningCertificate;
import dev.sigstore.rekor.client.*;
import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Date;
import java.time.Instant;
import java.util.Optional;

/** Verify hashrekords from rekor signed using the keyless signing flow with fulcio certificates. */
public class KeylessVerifier {
  private final FulcioVerifier fulcioVerifier;
  private final RekorVerifier rekorVerifier;
  private final RekorClient rekorClient;

  private KeylessVerifier(
      FulcioVerifier fulcioVerifier, RekorClient rekorClient, RekorVerifier rekorVerifier) {
    this.fulcioVerifier = fulcioVerifier;
    this.rekorClient = rekorClient;
    this.rekorVerifier = rekorVerifier;
  }

  public static KeylessVerifier.Builder builder() {
    return new KeylessVerifier.Builder();
  }

  public static class Builder {
    private FulcioVerifier fulcioVerifier;
    private RekorClient rekorClient;
    private RekorVerifier rekorVerifier;

    public KeylessVerifier.Builder fulcioVerifier(FulcioVerifier fulcioVerifier) {
      this.fulcioVerifier = fulcioVerifier;
      return this;
    }

    public KeylessVerifier.Builder rekorClient(
        RekorClient rekorClient, RekorVerifier rekorVerifier) {
      this.rekorClient = rekorClient;
      this.rekorVerifier = rekorVerifier;
      return this;
    }

    public KeylessVerifier build() {
      Preconditions.checkNotNull(fulcioVerifier);
      Preconditions.checkNotNull(rekorVerifier);
      Preconditions.checkNotNull(rekorClient);
      return new KeylessVerifier(fulcioVerifier, rekorClient, rekorVerifier);
    }

    public Builder sigstorePublicDefaults()
        throws IOException, InvalidAlgorithmParameterException, CertificateException,
            InvalidKeySpecException, NoSuchAlgorithmException {
      var fulcioCert =
          Resources.toByteArray(
              Resources.getResource("dev/sigstore/tuf/production/fulcio_v1.crt.pem"));
      var ctfePublicKey =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/production/ctfe.pub"));
      var rekorPublicKey =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/production/rekor.pub"));
      fulcioVerifier(FulcioVerifier.newFulcioVerifier(fulcioCert, ctfePublicKey));
      rekorClient(RekorClient.builder().build(), RekorVerifier.newRekorVerifier(rekorPublicKey));
      return this;
    }

    public Builder sigstoreStagingDefaults()
        throws IOException, InvalidAlgorithmParameterException, CertificateException,
            InvalidKeySpecException, NoSuchAlgorithmException {
      var fulcioCert =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/fulcio.crt.pem"));
      var ctfePublicKey =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/ctfe.pub"));
      var rekorPublicKey =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/rekor.pub"));
      fulcioVerifier(FulcioVerifier.newFulcioVerifier(fulcioCert, ctfePublicKey));
      rekorClient(
          RekorClient.builder().setServerUrl(URI.create(RekorClient.STAGING_REKOR_SERVER)).build(),
          RekorVerifier.newRekorVerifier(rekorPublicKey));
      return this;
    }
  }

  /**
   * Verify that the inputs can attest to the validity of a signature using sigstore's keyless
   * infrastructure. If no exception is thrown, it should be assumed verification has passed.
   *
   * @param artifactDigest the sha256 digest of the artifact that was signed
   * @param certChain the certificate chain obtained from a fulcio instance
   * @param signature the signature on the artifact
   * @throws KeylessVerificationException if the signing information could not be verified
   * @throws IOException if an error occurred communicating with remote rekor
   */
  public void verifyOnline(byte[] artifactDigest, byte[] certChain, byte[] signature)
      throws KeylessVerificationException, IOException {
    SigningCertificate signingCert;
    try {
      signingCert = SigningCertificate.from(Certificates.fromPemChain(certChain));
    } catch (CertificateException ex) {
      throw new KeylessVerificationException("Certificate was not valid: " + ex.getMessage(), ex);
    }
    var leafCert = signingCert.getLeafCertificate();

    // verify the certificate chains up to a trusted root (fulcio)
    try {
      fulcioVerifier.verifyCertChain(signingCert);
    } catch (FulcioVerificationException ex) {
      throw new KeylessVerificationException(
          "Fulcio certificate was not valid: " + ex.getMessage(), ex);
    }

    // make the sure a crt is signed by the certificate transparency log (embedded only)
    try {
      fulcioVerifier.verifySct(signingCert);
    } catch (FulcioVerificationException ex) {
      throw new KeylessVerificationException(
          "Fulcio certificate SCT was not valid: " + ex.getMessage(), ex);
    }

    // rebuild the hashedRekord so we can query the log for it
    var hashedRekordRequest =
        HashedRekordRequest.newHashedRekordRequest(
            artifactDigest, Certificates.toPemBytes(leafCert), signature);
    Optional<RekorEntry> rekorEntry;

    // attempt to grab the rekord from the rekor instance
    rekorEntry = rekorClient.getEntry(hashedRekordRequest);
    if (rekorEntry.isEmpty()) {
      throw new KeylessVerificationException("Rekor entry was not found");
    }

    // verify the rekor entry is signed by the log keys
    try {
      rekorVerifier.verifyEntry(rekorEntry.get());
    } catch (RekorVerificationException ex) {
      throw new KeylessVerificationException("Rekor entry signature was not valid");
    }

    // in online mode, currently, we verify the inclusion proof (this can maybe be optional)
    try {
      rekorVerifier.verifyInclusionProof(rekorEntry.get());
    } catch (RekorVerificationException ex) {
      throw new KeylessVerificationException("Rekor entry inclusion proof was not valid");
    }

    // check if the time of entry inclusion in the log (a stand-in for signing time) is within the
    // validity period for the certificate
    var entryTime = Date.from(Instant.ofEpochSecond(rekorEntry.get().getIntegratedTime()));
    try {
      leafCert.checkValidity(entryTime);
    } catch (CertificateNotYetValidException e) {
      throw new KeylessVerificationException("Signing time was before certificate validity", e);
    } catch (CertificateExpiredException e) {
      throw new KeylessVerificationException("Signing time was after certificate expiry", e);
    }

    // finally check the supplied signature can be verified by the public key in the certificate
    var publicKey = leafCert.getPublicKey();
    try {
      var verifier = Verifiers.INSTANCE.newVerifier(publicKey);
      if (!verifier.verifyDigest(artifactDigest, signature)) {
        throw new KeylessVerificationException("Artifact signature was not valid");
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new RuntimeException(ex);
    } catch (SignatureException ex) {
      throw new KeylessVerificationException(
          "Signature could not be processed: " + ex.getMessage(), ex);
    }
  }
}
