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

import com.google.api.client.http.*;
import com.google.common.io.CharStreams;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.cert.CertificateException;
import org.conscrypt.ct.SerializationException;

/** A client to communicate with a fulcio ca service instance. */
public class FulcioClient {
  public static final String PUBLIC_FULCIO_SERVER = "https://fulcio.sigstore.dev";
  public static final String STAGING_FULCIO_SERVER = "https://fulcio.sigstage.dev";
  public static final String SIGNING_CERT_PATH = "/api/v1/signingCert";
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

    /** Configure the http properties, see {@link HttpParams}, {@link ImmutableHttpParams}. */
    public Builder setHttpProvider(HttpParams httpParams) {
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

    public FulcioClient build() {
      return new FulcioClient(httpParams, serverUrl, requireSct);
    }
  }

  /**
   * Request a signing certificate from fulcio.
   *
   * @param cr certificate request parameters
   * @return a {@link SigningCertificate} from fulcio
   * @throws IOException if the http request fials
   * @throws CertificateException if returned certificates could not be decoded
   * @throws SerializationException if return sct could not be parsed
   */
  public SigningCertificate SigningCert(CertificateRequest cr)
      throws IOException, CertificateException, SerializationException {
    URI fulcioEndpoint = serverUrl.resolve(SIGNING_CERT_PATH);

    HttpRequest req =
        HttpClients.newHttpTransport(httpParams)
            .createRequestFactory()
            .buildPostRequest(
                new GenericUrl(fulcioEndpoint),
                ByteArrayContent.fromString("application/json", cr.toJsonPayload()));

    req.getHeaders().setAccept("application/pem-certificate-chain");
    req.getHeaders().setAuthorization("Bearer " + cr.getIdToken());

    HttpResponse resp = req.execute();
    if (resp.getStatusCode() != 201) {
      throw new IOException(
          String.format(
              "bad response from fulcio @ '%s' : %s", fulcioEndpoint, resp.parseAsString()));
    }

    String sctHeader = resp.getHeaders().getFirstHeaderStringValue("SCT");
    try (InputStream content = resp.getContent()) {
      var signingCert =
          SigningCertificate.newSigningCertificate(
              CharStreams.toString(new InputStreamReader(content, resp.getContentCharset())),
              sctHeader);
      if (signingCert.getDetachedSct().isEmpty() && !signingCert.hasEmbeddedSct() && requireSct) {
        throw new IOException(
            "no signed certificate timestamps were found in response from Fulcio");
      }
      return signingCert;
    }
  }
}
