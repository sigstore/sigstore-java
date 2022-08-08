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
import com.google.common.hash.Hashing;
import com.google.common.io.Resources;
import dev.sigstore.encryption.signers.Signer;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.fulcio.client.*;
import dev.sigstore.oidc.client.OidcClient;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.WebOidcClient;
import dev.sigstore.rekor.client.HashedRekordRequest;
import dev.sigstore.rekor.client.RekorClient;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.rekor.client.RekorVerifier;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.util.encoders.Hex;

/** A full sigstore keyless signing flow. */
public class KeylessSigner {
  private final FulcioClient fulcioClient;
  private final FulcioVerifier fulcioVerifier;
  private final RekorClient rekorClient;
  private final RekorVerifier rekorVerifier;
  private final OidcClient oidcClient;
  private final Signer signer;

  private KeylessSigner(
      FulcioClient fulcioClient,
      FulcioVerifier fulcioVerifier,
      RekorClient rekorClient,
      RekorVerifier rekorVerifier,
      OidcClient oidcClient,
      Signer signer) {
    this.fulcioClient = fulcioClient;
    this.fulcioVerifier = fulcioVerifier;
    this.rekorClient = rekorClient;
    this.rekorVerifier = rekorVerifier;
    this.oidcClient = oidcClient;
    this.signer = signer;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private FulcioClient fulcioClient;
    private FulcioVerifier fulcioVerifier;
    private RekorClient rekorClient;
    private RekorVerifier rekorVerifier;
    private OidcClient oidcClient;
    private Signer signer;

    public Builder fulcioClient(FulcioClient fulcioClient, FulcioVerifier fulcioVerifier) {
      this.fulcioClient = fulcioClient;
      this.fulcioVerifier = fulcioVerifier;
      return this;
    }

    public Builder rekorClient(RekorClient rekorClient, RekorVerifier rekorVerifier) {
      this.rekorClient = rekorClient;
      this.rekorVerifier = rekorVerifier;
      return this;
    }

    public Builder oidcClient(OidcClient oidcClient) {
      this.oidcClient = oidcClient;
      return this;
    }

    public Builder signer(Signer signer) {
      this.signer = signer;
      return this;
    }

    public KeylessSigner build() {
      Preconditions.checkNotNull(fulcioClient);
      Preconditions.checkNotNull(fulcioVerifier);
      Preconditions.checkNotNull(rekorClient);
      Preconditions.checkNotNull(rekorVerifier);
      Preconditions.checkNotNull(oidcClient);
      Preconditions.checkNotNull(signer);
      return new KeylessSigner(
          fulcioClient, fulcioVerifier, rekorClient, rekorVerifier, oidcClient, signer);
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
      fulcioClient(
          FulcioClient.builder().build(),
          FulcioVerifier.newFulcioVerifier(fulcioCert, ctfePublicKey));
      rekorClient(RekorClient.builder().build(), RekorVerifier.newRekorVerifier(rekorPublicKey));
      oidcClient(WebOidcClient.builder().build());
      signer(Signers.newEcdsaSigner());
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
      fulcioClient(
          FulcioClient.builder()
              .setServerUrl(URI.create(FulcioClient.STAGING_FULCIO_SERVER))
              .build(),
          FulcioVerifier.newFulcioVerifier(fulcioCert, ctfePublicKey));
      rekorClient(
          RekorClient.builder().setServerUrl(URI.create(RekorClient.STAGING_REKOR_SERVER)).build(),
          RekorVerifier.newRekorVerifier(rekorPublicKey));
      oidcClient(WebOidcClient.builder().setIssuer(WebOidcClient.STAGING_DEX_ISSUER).build());
      signer(Signers.newEcdsaSigner());
      return this;
    }
  }

  public KeylessSigningResult sign(Path artifact)
      throws OidcException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
          UnsupportedAlgorithmException, CertificateException, IOException,
          FulcioVerificationException, RekorVerificationException {
    var tokenInfo = oidcClient.getIDToken();
    var signingCert =
        fulcioClient.SigningCert(
            CertificateRequest.newCertificateRequest(
                signer.getPublicKey(),
                tokenInfo.getIdToken(),
                signer.sign(
                    tokenInfo.getSubjectAlternativeName().getBytes(StandardCharsets.UTF_8))));
    fulcioVerifier.verifyCertChain(signingCert);
    // TODO: this signing workflow mandates SCTs, but fulcio itself doesn't, figure out a way to
    // allow that to be known
    fulcioVerifier.verifySct(signingCert);

    var artifactByteSource = com.google.common.io.Files.asByteSource(artifact.toFile());
    var artifactDigest = artifactByteSource.hash(Hashing.sha256()).asBytes();
    byte[] signature;
    try (var stream = artifactByteSource.openStream()) {
      signature = signer.sign(stream);
    }
    var rekorRequest =
        HashedRekordRequest.newHashedRekordRequest(
            artifactDigest, signingCert.getLeafCertificate(), signature);
    var rekorResponse = rekorClient.putEntry(rekorRequest);
    rekorVerifier.verifyEntry(rekorResponse.getEntry());

    return ImmutableKeylessSigningResult.builder()
        .digest(Hex.toHexString(artifactDigest))
        .certPath(signingCert.getCertPath())
        .signature(signature)
        .entry(rekorResponse.getEntry())
        .build();
  }
}
