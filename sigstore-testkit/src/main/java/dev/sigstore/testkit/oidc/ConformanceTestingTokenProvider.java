package dev.sigstore.testkit.oidc;

import dev.sigstore.oidc.client.TokenStringOidcClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class ConformanceTestingTokenProvider implements TokenStringOidcClient.TokenStringProvider {

  public static ConformanceTestingTokenProvider newProvider() {
    return new ConformanceTestingTokenProvider();
  };

  @Override
  public String getTokenString() throws Exception {
    HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();
    URI fileUri = new URI("https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/refs/heads/current-token/oidc-token.txt");
    HttpRequest request = HttpRequest.newBuilder()
                                .uri(fileUri)
                                .GET() // Specifies a GET request
                                .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    if (response.statusCode() != 200) {
      throw new IOException("Failed to read remote test oidc token");
    }
    var body = response.body();
    return body;
  }
}
