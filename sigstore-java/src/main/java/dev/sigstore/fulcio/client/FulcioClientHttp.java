/*
 * Copyright 2026 The Sigstore Authors.
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
import static dev.sigstore.fulcio.v2.SigningCertificate.CertificateCase.SIGNED_CERTIFICATE_EMBEDDED_SCT;

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.util.Preconditions;
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.fulcio.v2.CertificateChain;
import dev.sigstore.fulcio.v2.CreateSigningCertificateRequest;
import dev.sigstore.fulcio.v2.PublicKey;
import dev.sigstore.fulcio.v2.PublicKeyRequest;
import dev.sigstore.fulcio.v2.SigningCertificate;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.trustroot.Service;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;

/** A client to communicate with a fulcio service instance over HTTP. */
public class FulcioClientHttp implements FulcioClient {
  public static final String FULCIO_SIGNING_CERT_PATH = "/api/v2/signingCert";

  private final HttpParams httpParams;
  private final URI uri;

  public static Builder builder() {
    return new Builder();
  }

  private FulcioClientHttp(HttpParams httpParams, URI uri) {
    this.uri = uri;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private HttpParams httpParams = HttpParams.builder().build();
    private Service service;

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}. */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** Service information for a remote fulcio instance. */
    public Builder setService(Service service) {
      this.service = service;
      return this;
    }

    public FulcioClientHttp build() {
      Preconditions.checkNotNull(service);
      return new FulcioClientHttp(httpParams, service.getUrl());
    }
  }

  /**
   * Request a signing certificate from fulcio over HTTP.
   *
   * @param request certificate request parameters
   * @return a {@link CertPath} from fulcio
   */
  @Override
  public CertPath signingCertificate(CertificateRequest request) throws CertificateException {
    URI endpoint = uri.resolve(FULCIO_SIGNING_CERT_PATH);

    String pemEncodedPublicKey =
        "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getEncoder().encodeToString(request.getPublicKey().getEncoded())
            + "\n-----END PUBLIC KEY-----";

    var createSigningCertificateRequest =
        CreateSigningCertificateRequest.newBuilder()
            .setPublicKeyRequest(
                PublicKeyRequest.newBuilder()
                    .setPublicKey(
                        PublicKey.newBuilder()
                            .setAlgorithm(request.getPublicKeyAlgorithm())
                            .setContent(pemEncodedPublicKey)
                            .build())
                    .setProofOfPossession(ByteString.copyFrom(request.getProofOfPossession()))
                    .build())
            .build();

    String jsonPayload;
    try {
      jsonPayload = JsonFormat.printer().print(createSigningCertificateRequest);
    } catch (InvalidProtocolBufferException e) {
      throw new CertificateException("Failed to serialize certificate request", e);
    }

    String responseJson;
    try {
      var httpRequest =
          HttpClients.newRequestFactory(httpParams)
              .buildPostRequest(
                  new GenericUrl(endpoint),
                  ByteArrayContent.fromString("application/json", jsonPayload));
      httpRequest.getHeaders().set("Accept", "application/json");
      httpRequest.getHeaders().set("Content-Type", "application/json");
      httpRequest.getHeaders().set("Authorization", "Bearer " + request.getIdToken());

      var resp = httpRequest.execute();
      if (resp.getStatusCode() != 200) {
        throw new CertificateException(
            String.format(
                Locale.ROOT,
                "bad response from fulcio @ '%s' : %s",
                endpoint,
                resp.parseAsString()));
      }
      responseJson = resp.parseAsString();
    } catch (IOException e) {
      throw new CertificateException("Failed to request signing certificate from fulcio", e);
    }

    var signingCertBuilder = SigningCertificate.newBuilder();
    try {
      ProtoJson.parser().merge(responseJson, signingCertBuilder);
    } catch (InvalidProtocolBufferException e) {
      throw new CertificateException("Failed to parse signing certificate response from fulcio", e);
    }
    var signingCert = signingCertBuilder.build();

    if (signingCert.getCertificateCase() == SIGNED_CERTIFICATE_DETACHED_SCT) {
      throw new CertificateException("Detached SCTs are not supported");
    }
    if (signingCert.getCertificateCase() != SIGNED_CERTIFICATE_EMBEDDED_SCT) {
      throw new CertificateException("No certificate was found in response from fulcio");
    }

    return decodeCerts(signingCert.getSignedCertificateEmbeddedSct().getChain());
  }

  @VisibleForTesting
  CertPath decodeCerts(CertificateChain certChain) throws CertificateException {
    var certificateFactory = CertificateFactory.getInstance("X.509");
    var certs = new ArrayList<X509Certificate>();
    if (certChain.getCertificatesCount() == 0) {
      throw new CertificateParsingException(
          "no valid PEM certificates were found in response from Fulcio");
    }
    for (var cert : certChain.getCertificatesList()) {
      certs.add(
          (X509Certificate)
              certificateFactory.generateCertificate(
                  new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8))));
    }
    return certificateFactory.generateCertPath(certs);
  }
}
