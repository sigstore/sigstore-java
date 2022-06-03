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

import com.google.api.client.http.*;
import dev.sigstore.http.HttpProvider;
import dev.sigstore.json.GsonSupplier;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/** A client to communicate with a rekor service instance. */
public class RekorClient {
  public static final String PUBLIC_REKOR_SERVER = "https://rekor.sigstore.dev";
  public static final String REKOR_ENTRIES_PATH = "/api/v1/log/entries";
  public static final String REKOR_ENTRIES_GET_PATH = "/api/v1/log/entries/";
  public static final String REKOR_INDEX_SEARCH_PATH = "/api/v1/index/retrieve";

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

  /**
   * Put a new hashedrekord entry on the Rekor log.
   *
   * @param hashedRekordRequest the request to send to rekor
   * @return a {@link RekorResponse} with information about the log entry
   */
  public RekorResponse putEntry(HashedRekordRequest hashedRekordRequest) throws IOException {
    URI rekorPutEndpoint = serverUrl.resolve(REKOR_ENTRIES_PATH);

    HttpRequest req =
        httpProvider
            .getHttpTransport()
            .createRequestFactory()
            .buildPostRequest(
                new GenericUrl(rekorPutEndpoint),
                ByteArrayContent.fromString(
                    "application/json", hashedRekordRequest.toJsonPayload()));
    req.getHeaders().set("Accept", "application/json");
    req.getHeaders().set("Content-Type", "application/json");

    HttpResponse resp = req.execute();
    if (resp.getStatusCode() != 201) {
      throw new IOException(
          String.format(
              "bad response from rekor @ '%s' : %s", rekorPutEndpoint, resp.parseAsString()));
    }

    URI rekorEntryUri = serverUrl.resolve(resp.getHeaders().getLocation());
    String entry = resp.parseAsString();
    return RekorResponse.newRekorResponse(rekorEntryUri, entry);
  }

  public RekorEntry getEntry(String UUID) throws IOException {
    URI getEntryURI = serverUrl.resolve(REKOR_ENTRIES_GET_PATH + UUID);
    HttpRequest req =
        httpProvider
            .getHttpTransport()
            .createRequestFactory()
            .buildGetRequest(new GenericUrl(getEntryURI));
    req.getHeaders().set("Accept", "application/json");
    HttpResponse response;
    try {
      response = req.execute();
    } catch (HttpResponseException e) {
      if (e.getStatusCode() == 404) return null;
      throw e;
    }
    return RekorResponse.newRekorResponse(getEntryURI, response.parseAsString()).getEntry();
  }

  /**
   * Returns a list of UUIDs for matching entries for the given search parameters.
   *
   * @param email the OIDC email subject
   * @param hash sha256 hash of the artifact
   * @param publicKeyFormat format of public key (one of 'pgp','x509','minisign', 'ssh', 'tuf')
   * @param publicKeyContent public key base64 encoded content
   */
  public List<String> searchEntry(
      String email, String hash, String publicKeyFormat, String publicKeyContent)
      throws IOException {
    URI rekorSearchEndpoint = serverUrl.resolve(REKOR_INDEX_SEARCH_PATH);

    HashMap<String, Object> publicKeyParams = null;
    if (publicKeyContent != null) {
      publicKeyParams = new HashMap<>();
      publicKeyParams.put("format", publicKeyFormat);
      publicKeyParams.put("content", publicKeyContent);
    }
    var data = new HashMap<String, Object>();
    data.put("email", email);
    data.put("hash", hash);
    data.put("publicKey", publicKeyParams);

    GsonSupplier gsonSupplier = new GsonSupplier();
    String contentString = gsonSupplier.get().toJson(data);
    System.out.println(contentString);
    HttpRequest req =
        httpProvider
            .getHttpTransport()
            .createRequestFactory()
            .buildPostRequest(
                new GenericUrl(rekorSearchEndpoint),
                ByteArrayContent.fromString("application/json", contentString));
    req.getHeaders().set("Accept", "application/json");
    req.getHeaders().set("Content-Type", "application/json");
    var response = req.execute();
    return Arrays.asList(gsonSupplier.get().fromJson(response.parseAsString(), String[].class));
  }
}
