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

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import java.util.concurrent.TimeUnit;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;

public class HttpProvider {
  public static final String DEFAULT_USER_AGENT = "sigstoreJavaClient/0.0.1";
  public static final int DEFAULT_TIMEOUT = 60;
  public static final boolean DEFAULT_USE_SSL = true;

  private final HttpTransport httpTransport;

  public static HttpProvider.Builder builder() {
    return new Builder();
  }

  private HttpProvider(HttpTransport httpTransport) {
    this.httpTransport = httpTransport;
  }

  public HttpTransport getHttpTransport() {
    return httpTransport;
  }

  public static class Builder {
    private long timeout = DEFAULT_TIMEOUT;
    private String userAgent = DEFAULT_USER_AGENT;
    private boolean useSSLVerification = DEFAULT_USE_SSL;

    private Builder() {}

    /** A non negative timeout for each requests, defaults to {@value DEFAULT_TIMEOUT}. */
    public HttpProvider.Builder setTimeout(long timeout) {
      if (timeout < 0) {
        throw new IllegalArgumentException("Invalid timeout: " + timeout);
      }
      this.timeout = timeout;
      return this;
    }

    /** User agent string to include in requests, defaults to {@value DEFAULT_USER_AGENT}. */
    public HttpProvider.Builder setUserAgent(String userAgent) {
      if (userAgent == null || userAgent.trim().isEmpty()) {
        throw new IllegalArgumentException("Invalid useragent: " + userAgent);
      }
      this.userAgent = userAgent;
      return this;
    }

    /**
     * Configure SSL verification, there's probably not many good reason to turn this off, defaults
     * to {@value DEFAULT_USE_SSL}
     */
    public HttpProvider.Builder setUseSSLVerification(boolean enable) {
      this.useSSLVerification = enable;
      return this;
    }

    public HttpProvider build() {
      HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
      hcb.setConnectionTimeToLive(timeout, TimeUnit.SECONDS);
      if (!useSSLVerification) {
        hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
      }
      hcb.setUserAgent(userAgent);
      HttpTransport httpTransport = new ApacheHttpTransport(hcb.build());
      return new HttpProvider(httpTransport);
    }
  }
}
