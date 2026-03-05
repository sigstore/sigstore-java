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
package dev.sigstore.http;

import com.google.api.client.http.HttpBackOffIOExceptionHandler;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v5.Apache5HttpTransport;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.ObjectParser;
import dev.sigstore.forbidden.SuppressForbidden;
import javax.annotation.Nullable;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.util.TimeValue;

/** HttpClients generates Google Http Client objects from configuration. */
public class HttpClients {

  /**
   * Build a transport, you probably want to use {@link #newRequestFactory(HttpParams)} to
   * instantiate GET and POST requests or use {@link #newRequestFactory(HttpParams, ObjectParser) if
   * you need to also configure the response parser}.
   */
  public static HttpTransport newHttpTransport(HttpParams httpParams) {
    if (httpParams.getAllowInsecureConnections()) {
      var connManager =
          PoolingHttpClientConnectionManagerBuilder.create()
              .setSSLSocketFactory(
                  SSLConnectionSocketFactoryBuilder.create()
                      .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                      .build())
              .setMaxConnTotal(200)
              .setMaxConnPerRoute(20)
              .setDefaultConnectionConfig(
                  ConnectionConfig.custom()
                      .setTimeToLive(TimeValue.NEG_ONE_MILLISECOND)
                      .setValidateAfterInactivity(TimeValue.NEG_ONE_MILLISECOND)
                      .build())
              .build();
      return new Apache5HttpTransport(
          Apache5HttpTransport.newDefaultHttpClientBuilder()
              .setConnectionManager(connManager)
              .build());
    }
    return new Apache5HttpTransport(Apache5HttpTransport.newDefaultHttpClientBuilder().build());
  }

  /** Create a new get requests with the httpParams applied and retries. */
  @SuppressForbidden(reason = "HttpClients#newHttpTransport(HttpParams)")
  public static HttpRequestFactory newRequestFactory(HttpParams httpParams) {
    return newRequestFactory(httpParams, null);
  }

  /** Create a new get requests with the httpParams applied, retries and a response parser. */
  @SuppressForbidden(reason = "HttpClients#newHttpTransport(HttpParams)")
  public static HttpRequestFactory newRequestFactory(
      HttpParams httpParams, @Nullable ObjectParser responseParser) {
    return HttpClients.newHttpTransport(httpParams)
        .createRequestFactory(
            request -> {
              request.setSuppressUserAgentSuffix(true);
              request.getHeaders().set(HttpHeaders.USER_AGENT, httpParams.getUserAgent());
              request.setConnectTimeout(httpParams.getTimeout() * 1000);
              request.setReadTimeout(httpParams.getTimeout() * 1000);
              request.setNumberOfRetries(3); // arbitrarily selected number of retries
              request.setUnsuccessfulResponseHandler(
                  UnsuccessfulResponseHandler.newUnsuccessfulResponseHandler());
              request.setIOExceptionHandler(
                  new HttpBackOffIOExceptionHandler(new ExponentialBackOff()));
              if (responseParser != null) {
                request.setParser(responseParser);
              }
            });
  }
}
