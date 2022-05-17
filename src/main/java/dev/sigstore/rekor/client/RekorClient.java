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
package dev.sigstore.rekor.client;

import dev.sigstore.http.HttpProvider;
import java.net.URI;

/** A client to communicate with a rekor service instance. */
public class RekorClient {
  public static final String PUBLIC_REKOR_SERVER = "https://rekor.sigstore.dev";

  private final HttpProvider httpProvider;
  private final URI serverUrl;

  public static RekorClient.Builder builder() {
    return new RekorClient.Builder();
  }

  private RekorClient(HttpProvider httpProvider, URI serverUrl) {
    this.serverUrl = serverUrl;
    this.httpProvider = httpProvider;
  }

  public static class Builder {
    private URI serverUrl = URI.create(PUBLIC_REKOR_SERVER);
    private HttpProvider httpProvider;

    private Builder() {}

    /** Configure the http properties, see {@link HttpProvider}. */
    public RekorClient.Builder setHttpProvider(HttpProvider httpConfiguration) {
      this.httpProvider = httpConfiguration;
      return this;
    }

    /** The fulcio remote server URI, defaults to {@value PUBLIC_REKOR_SERVER}. */
    public RekorClient.Builder setServerUrl(URI uri) {
      this.serverUrl = uri;
      return this;
    }

    public RekorClient build() {
      HttpProvider hp = httpProvider != null ? httpProvider : HttpProvider.builder().build();
      return new RekorClient(hp, serverUrl);
    }
  }

  /** Put an entry on rekor. */
  public void putEntry() {
    throw new UnsupportedOperationException("I'm a worthless upload function");
  }

  /** Obtain an entry for an artifact from rekor. */
  public void getEntry() {
    throw new UnsupportedOperationException("I'm a worthless download function");
  }
}
