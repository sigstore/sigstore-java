/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.testkit.oidc;

import dev.sigstore.oidc.client.TokenStringOidcClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * A token provider that will grab the "unsafe" token from sigstore github conformance testing. This
 * should never be used by actual signers and should only be available in tests. Use this with the
 * {@link TokenStringOidcClient}.
 */
public class ConformanceTestingTokenProvider implements TokenStringOidcClient.TokenStringProvider {

  public static ConformanceTestingTokenProvider newProviderFromGithub() {
    return new ConformanceTestingTokenProvider(
        "https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/refs/heads/current-token/oidc-token.txt");
  }

  public static ConformanceTestingTokenProvider newProviderFromGcp() {
    return new ConformanceTestingTokenProvider(
        "https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt");
  }

  private final String tokenUrl;

  private ConformanceTestingTokenProvider(String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  @Override
  public String getTokenString() throws Exception {
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    URI fileUri = new URI(tokenUrl);
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(fileUri)
            .GET() // Specifies a GET request
            .build();
    HttpResponse<String> response =
        client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    if (response.statusCode() != 200) {
      throw new IOException("Failed to read remote test oidc token");
    }
    return response.body();
  }
}
