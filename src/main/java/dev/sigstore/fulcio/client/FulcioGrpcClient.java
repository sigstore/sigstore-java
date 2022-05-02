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

import com.google.protobuf.ByteString;
import dev.sigstore.fulcio.v2.*;
import dev.sigstore.http.GrpcChannels;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.conscrypt.ct.SerializationException;

/**
 * A client to communicate with a fulcio ca service instance over grpc. This should replace {@link
 * FulcioClient}, we do not need to maintain both client implementations.
 */
public class FulcioGrpcClient {
  public static final String PUBLIC_FULCIO_SERVER = "https://fulcio.sigstore.dev";
  public static final boolean DEFAULT_REQUIRE_SCT = true;

  private final HttpParams httpParams;
  private final URI serverUrl;
  private final boolean requireSct;

  public static Builder builder() {
    return new Builder();
  }

  private FulcioGrpcClient(HttpParams httpParams, URI serverUrl, boolean requireSct) {
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

    /** The fulcio remote server URI, defaults to {@value PUBLIC_FULCIO_SERVER}. */
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

    public FulcioGrpcClient build() {
      return new FulcioGrpcClient(httpParams, serverUrl, requireSct);
    }
  }

  /**
   * Request a signing certificate from fulcio.
   *
   * @param cr certificate request parameters
   * @return a {@link SigningCertificate} from fulcio
   */
  public SigningCertificate SigningCert(CertificateRequest cr)
      throws InterruptedException, SerializationException, CertificateException, IOException {
    // TODO: we should reuse this message channel across various executions of this client and
    // add a client shutdown method instead of encapsulating it all in here
    var channel = GrpcChannels.newManagedChannel(serverUrl, httpParams);

    try {
      var client = CAGrpc.newBlockingStub(channel);
      System.out.println(
          new String(new X509EncodedKeySpec(cr.getPublicKey().getEncoded()).getEncoded()));
      var credentials = Credentials.newBuilder().setOidcIdentityToken(cr.getIdToken()).build();

      String pemEncodedPublicKey =
          "-----BEGIN PUBLIC KEY-----\n"
              + Base64.getEncoder().encodeToString(cr.getPublicKey().getEncoded())
              + "\n-----END PUBLIC KEY-----";
      var publicKeyRequest =
          PublicKeyRequest.newBuilder()
              .setPublicKey(
                  PublicKey.newBuilder()
                      .setAlgorithm(PublicKeyAlgorithm.ECDSA)
                      .setContent(pemEncodedPublicKey)
                      .build())
              .setProofOfPossession(ByteString.copyFrom(cr.getProofOfPossession()))
              .build();
      var req =
          CreateSigningCertificateRequest.newBuilder()
              .setCredentials(credentials)
              .setPublicKeyRequest(publicKeyRequest)
              .build();

      var certs = client.createSigningCertificate(req);

      switch (certs.getCertificateCase()) {
        case SIGNED_CERTIFICATE_DETACHED_SCT:
          if (certs.getSignedCertificateDetachedSct().getSignedCertificateTimestamp().isEmpty()
              && requireSct) {
            throw new IOException(
                "no signed certificate timestamps were found in response from Fulcio");
          }
          return SigningCertificate.newSigningCertificate(certs.getSignedCertificateDetachedSct());
        case SIGNED_CERTIFICATE_EMBEDDED_SCT:
        default:
          return SigningCertificate.newSigningCertificate(certs.getSignedCertificateEmbeddedSct());
      }

    } finally {
      channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
  }
}
