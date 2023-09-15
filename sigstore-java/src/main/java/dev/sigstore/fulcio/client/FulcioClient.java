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

import static dev.sigstore.fulcio.v2.SigningCertificate.CertificateCase.SIGNED_CERTIFICATE_DETACHED_SCT;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.fulcio.v2.CAGrpc;
import dev.sigstore.fulcio.v2.CertificateChain;
import dev.sigstore.fulcio.v2.CreateSigningCertificateRequest;
import dev.sigstore.fulcio.v2.Credentials;
import dev.sigstore.fulcio.v2.PublicKey;
import dev.sigstore.fulcio.v2.PublicKeyRequest;
import dev.sigstore.http.GrpcChannels;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.trustroot.CertificateAuthority;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/** A client to communicate with a fulcio service instance over gRPC. */
public class FulcioClient {

  private final HttpParams httpParams;
  private final CertificateAuthority certificateAuthority;

  public static Builder builder() {
    return new Builder();
  }

  private FulcioClient(HttpParams httpParams, CertificateAuthority certificateAuthority) {
    this.certificateAuthority = certificateAuthority;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private CertificateAuthority certificateAuthority;
    private HttpParams httpParams = ImmutableHttpParams.builder().build();

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}. */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** The remote fulcio instance. */
    public Builder setCertificateAuthority(CertificateAuthority certificateAuthority) {
      this.certificateAuthority = certificateAuthority;
      return this;
    }

    /** The remote fulcio instance inferred from a trustedRoot. */
    public Builder setCertificateAuthority(SigstoreTrustedRoot trustedRoot) {
      this.certificateAuthority = trustedRoot.getCAs().current();
      return this;
    }

    public FulcioClient build() {
      return new FulcioClient(httpParams, certificateAuthority);
    }
  }

  /**
   * Request a signing certificate from fulcio.
   *
   * @param request certificate request parameters
   * @return a {@link CertPath} from fulcio
   */
  public CertPath signingCertificate(CertificateRequest request)
      throws InterruptedException, CertificateException {
    if (!certificateAuthority.isCurrent()) {
      throw new RuntimeException(
          "Certificate Authority '" + certificateAuthority.getUri() + "' is not current");
    }
    // TODO: 1. If we want to reduce the cost of creating channels/connections, we could try
    // to make a new connection once per batch of fulcio requests, but we're not really
    // at that point yet.
    // TODO: 2. getUri().getAuthority() is potentially prone to error if we don't get a good URI
    var channel =
        GrpcChannels.newManagedChannel(certificateAuthority.getUri().getAuthority(), httpParams);

    try {
      var client = CAGrpc.newBlockingStub(channel);
      var credentials = Credentials.newBuilder().setOidcIdentityToken(request.getIdToken()).build();

      String pemEncodedPublicKey =
          "-----BEGIN PUBLIC KEY-----\n"
              + Base64.getEncoder().encodeToString(request.getPublicKey().getEncoded())
              + "\n-----END PUBLIC KEY-----";
      var publicKeyRequest =
          PublicKeyRequest.newBuilder()
              .setPublicKey(
                  PublicKey.newBuilder()
                      .setAlgorithm(request.getPublicKeyAlgorithm())
                      .setContent(pemEncodedPublicKey)
                      .build())
              .setProofOfPossession(ByteString.copyFrom(request.getProofOfPossession()))
              .build();
      var req =
          CreateSigningCertificateRequest.newBuilder()
              .setCredentials(credentials)
              .setPublicKeyRequest(publicKeyRequest)
              .build();

      var certs =
          client
              .withDeadlineAfter(httpParams.getTimeout(), TimeUnit.SECONDS)
              .createSigningCertificate(req);

      if (certs.getCertificateCase() == SIGNED_CERTIFICATE_DETACHED_SCT) {
        throw new CertificateException("Detached SCTs are not supported");
      }
      return Certificates.trimParent(
          decodeCerts(certs.getSignedCertificateEmbeddedSct().getChain()),
          certificateAuthority.getCertPath());
    } finally {
      channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  @VisibleForTesting
  CertPath decodeCerts(CertificateChain certChain) throws CertificateException {
    var certificateFactory = CertificateFactory.getInstance("X.509");
    var certs = new ArrayList<X509Certificate>();
    if (certChain.getCertificatesCount() == 0) {
      throw new CertificateParsingException(
          "no valid PEM certificates were found in response from Fulcio");
    }
    for (var cert : certChain.getCertificatesList().asByteStringList()) {
      certs.add(
          (X509Certificate)
              certificateFactory.generateCertificate(new ByteArrayInputStream(cert.toByteArray())));
    }
    return certificateFactory.generateCertPath(certs);
  }
}
