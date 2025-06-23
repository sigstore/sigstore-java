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

import com.google.api.client.util.Preconditions;
import dev.sigstore.buildinfo.BuildInfo;
import org.immutables.value.Value;

/**
 * Http parameters for configuring connections to remote services. Use {@link ImmutableHttpParams}
 * to instantiate.
 */
@Value.Immutable
public abstract class HttpParams {
  static final String DEFAULT_USER_AGENT = "sigstoreJavaClient/" + BuildInfo.VERSION;
  static final int DEFAULT_TIMEOUT = 60;
  static final boolean DEFAULT_ALLOW_INSECURE_CONNECTIONS = false;

  @Value.Default
  public String getUserAgent() {
    return DEFAULT_USER_AGENT;
  }

  @Value.Default
  public int getTimeout() {
    return DEFAULT_TIMEOUT;
  }

  /**
   * You shouldn't be using this outside of testing or very specific environments, but allows grpc
   * or http clients to connect without ssl/tls.
   */
  @Value.Default
  public boolean getAllowInsecureConnections() {
    return DEFAULT_ALLOW_INSECURE_CONNECTIONS;
  }

  @Value.Check
  protected void check() {
    Preconditions.checkState(getTimeout() > 0, "'timeout' should be greater than zero");
    Preconditions.checkState(!getUserAgent().isEmpty(), "'useragent' must not be empty");
  }

  public static ImmutableHttpParams.Builder builder() {
    return ImmutableHttpParams.builder();
  }
}
