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
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.common.io.CharStreams;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.conscrypt.ct.SerializationException;

public class FulcioClient {
  public static final String PUBLIC_FULCIO_SERVER = "https://fulcio.sigstore.dev";
  public static final String SIGNING_CERT_PATH = "/api/v1/signingCert";
  public static final String DEFAULT_USER_AGENT = "fulcioJavaClient/0.0.1";
  public static final int DEFAULT_TIMEOUT = 60;

  private final HttpTransport httpTransport;
  private final URI serverUrl;
  private final String userAgent;
  private final boolean requireSct;

  public static Builder builder() {
    return new Builder();
  }

  private FulcioClient(
      HttpTransport httpTransport, URI serverUrl, String userAgent, boolean requireSct) {
    this.httpTransport = httpTransport;
    this.serverUrl = serverUrl;
    this.userAgent = userAgent;
    this.requireSct = requireSct;
  }

  public static class Builder {
    private long timeout = DEFAULT_TIMEOUT;
    private URI serverUrl = URI.create(PUBLIC_FULCIO_SERVER);
    private String userAgent = DEFAULT_USER_AGENT;
    private boolean useSSLVerification = true;
    private boolean requireSct = true;

    private Builder() {}

    public Builder setTimeout(long timeout) {
      if (timeout < 0) {
        throw new IllegalArgumentException("Invalid timeout: " + timeout);
      }
      this.timeout = timeout;
      return this;
    }

    public Builder setServerUrl(URI uri) {
      this.serverUrl = uri;
      return this;
    }

    public Builder setUserAgent(String userAgent) {
      if (userAgent == null || userAgent.trim().isEmpty()) {
        throw new IllegalArgumentException("Invalid useragent: " + userAgent);
      }
      this.userAgent = userAgent;
      return this;
    }

    public Builder setUseSSLVerification(boolean enable) {
      this.useSSLVerification = enable;
      return this;
    }

    public Builder requireSct(boolean requireSct) {
      this.requireSct = requireSct;
      return this;
    }

    public FulcioClient build() {
      HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
      hcb.setConnectionTimeToLive(timeout, TimeUnit.SECONDS);
      if (!useSSLVerification) {
        hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
      }
      HttpTransport httpTransport = new ApacheHttpTransport(hcb.build());
      return new FulcioClient(httpTransport, serverUrl, userAgent, requireSct);
    }
  }

  public SigningCertificate SigningCert(CertificateRequest cr, String bearerToken)
      throws IOException, CertificateException, SerializationException {
    URI fulcioEndpoint = serverUrl.resolve(SIGNING_CERT_PATH);

    HttpRequest req =
        httpTransport
            .createRequestFactory()
            .buildPostRequest(
                new GenericUrl(fulcioEndpoint),
                ByteArrayContent.fromString("application/json", cr.toJsonPayload()));

    req.getHeaders().setAccept("application/pem-certificate-chain");
    req.getHeaders().setAuthorization("Bearer " + bearerToken);

    HttpResponse resp = req.execute();
    if (resp.getStatusCode() != 201) {
      throw new IOException(
          String.format(
              "bad response from fulcio @ '%s' : %s", fulcioEndpoint, resp.parseAsString()));
    }

    String sctHeader = resp.getHeaders().getFirstHeaderStringValue("SCT");
    if (sctHeader == null && requireSct) {
      throw new IOException("no signed certificate timestamps were found in response from Fulcio");
    }

    try (InputStream content = resp.getContent()) {
      return SigningCertificate.newSigningCertificate(
          CharStreams.toString(new InputStreamReader(content, resp.getContentCharset())),
          sctHeader);
    }
  }
}
