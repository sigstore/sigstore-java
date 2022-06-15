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

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.net.URI;
import java.util.concurrent.TimeUnit;

public class GrpcChannels {
  /**
   * Create a new managed channel, this may be reused across multiple requests to a host, and must
   * be closed when finished.
   *
   * @param serverUrl the host to connect to
   * @param httpParams the http configuration
   * @return a reusable grpc channel
   */
  public static ManagedChannel newManagedChannel(URI serverUrl, HttpParams httpParams) {
    var channelBuilder =
        ManagedChannelBuilder.forTarget(serverUrl.toString())
            .userAgent(httpParams.getUserAgent())
            .keepAliveTimeout(httpParams.getTimeout(), TimeUnit.SECONDS);
    if (httpParams.getAllowInsecureConnections()) {
      channelBuilder.usePlaintext();
    }
    return channelBuilder.build();
  }
}
