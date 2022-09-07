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

import static dev.sigstore.fulcio.v2.SigningCertificate.CertificateCase.*;

import com.google.protobuf.ByteString;
import dev.sigstore.encryption.certificates.transparency.SerializationException;
import dev.sigstore.fulcio.v2.*;
import dev.sigstore.http.GrpcChannels;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/** A client to communicate with a fulcio service instance over gRPC. */
public class FulcioClient {
  // GRPC explicitly doesn't want https:// in the server address, so it is not included
  public static final String PUBLIC_FULCIO_SERVER = "fulcio.sigstore.dev";
  public static final String STAGING_FULCIO_SERVER = "fulcio.sigstage.dev";
  public static final boolean DEFAULT_REQUIRE_SCT = true;

  private final HttpParams httpParams;
  private final URI serverUrl;
  private final boolean requireSct;

  public static Builder builder() {
    return new Builder();
  }

  private FulcioClient(HttpParams httpParams, URI serverUrl, boolean requireSct) {
    this.serverUrl = serverUrl;
    this.requireSct = requireSct;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private URI serverUrl = URI.create(PUBLIC_FULCIO_SERVER);
    private boolean requireSct = DEFAULT_REQUIRE_SCT;
    private HttpParams httpParams = ImmutableHttpParams.builder().build();

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}. */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /**
     * The fulcio remote server URI, defaults to {@value PUBLIC_FULCIO_SERVER}. Do not include
     * http:// or https:// in the server URL.
     */
    public Builder setServerUrl(URI uri) {
      this.serverUrl = uri;
      return this;
    }

    /**
     * Configure whether we should expect the fulcio instance to return an sct with the signing
     * certificate, defaults to {@value DEFAULT_REQUIRE_SCT}.
     */
    public Builder requireSct(boolean requireSct) {
      this.requireSct = requireSct;
      return this;
    }

    public FulcioClient build() {
      return new FulcioClient(httpParams, serverUrl, requireSct);
    }
  }

  /**
   * Request a signing certificate from fulcio.
   *
   * @param request certificate request parameters
   * @return a {@link SigningCertificate} from fulcio
   */
  public SigningCertificate signingCertificate(CertificateRequest request)
      throws InterruptedException, CertificateException, IOException {
    // TODO: If we want to reduce the cost of creating channels/connections, we could try
    // to make a new connection once per batch of fulcio requests, but we're not really
    // at that point yet.
    var channel = GrpcChannels.newManagedChannel(serverUrl, httpParams);

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

      var certs = client.createSigningCertificate(req);

      if (certs.getCertificateCase() == SIGNED_CERTIFICATE_DETACHED_SCT) {
        if (certs.getSignedCertificateDetachedSct().getSignedCertificateTimestamp().isEmpty()
            && requireSct) {
          throw new CertificateException(
              "no signed certificate timestamps were found in response from Fulcio");
        }
        try {
          return SigningCertificate.newSigningCertificate(certs.getSignedCertificateDetachedSct());
        } catch (SerializationException se) {
          throw new CertificateException("Could not parse detached SCT");
        }
      } else {
        return SigningCertificate.newSigningCertificate(certs.getSignedCertificateEmbeddedSct());
      }

    } finally {
      channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
  }
}
