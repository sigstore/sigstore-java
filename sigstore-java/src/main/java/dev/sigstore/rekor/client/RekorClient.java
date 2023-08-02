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

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.api.client.http.*;
import com.google.gson.JsonSyntaxException;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import java.io.IOException;
import java.net.URI;
import java.util.*;

/** A client to communicate with a rekor service instance. */
public class RekorClient {
  public static final String PUBLIC_REKOR_SERVER = "https://rekor.sigstore.dev";
  public static final String STAGING_REKOR_SERVER = "https://rekor.sigstage.dev";
  public static final String REKOR_ENTRIES_PATH = "/api/v1/log/entries";
  public static final String REKOR_INDEX_SEARCH_PATH = "/api/v1/index/retrieve";

  private final HttpParams httpParams;
  private final URI serverUrl;

  public static RekorClient.Builder builder() {
    return new RekorClient.Builder();
  }

  private RekorClient(HttpParams httpParams, URI serverUrl) {
    this.serverUrl = serverUrl;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private URI serverUrl = URI.create(PUBLIC_REKOR_SERVER);
    private HttpParams httpParams = ImmutableHttpParams.builder().build();

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}, {@link ImmutableHttpParams}. */
    public RekorClient.Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** The fulcio remote server URI, defaults to {@value PUBLIC_REKOR_SERVER}. */
    public RekorClient.Builder setServerUrl(URI uri) {
      this.serverUrl = uri;
      return this;
    }

    public RekorClient build() {
      return new RekorClient(httpParams, serverUrl);
    }
  }

  /**
   * Put a new hashedrekord entry on the Rekor log.
   *
   * @param hashedRekordRequest the request to send to rekor
   * @return a {@link RekorResponse} with information about the log entry
   */
  public RekorResponse putEntry(HashedRekordRequest hashedRekordRequest)
      throws IOException, RekorParseException {
    URI rekorPutEndpoint = serverUrl.resolve(REKOR_ENTRIES_PATH);

    HttpRequest req =
        HttpClients.newRequestFactory(httpParams)
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
              Locale.ROOT,
              "bad response from rekor @ '%s' : %s",
              rekorPutEndpoint,
              resp.parseAsString()));
    }

    URI rekorEntryUri = serverUrl.resolve(resp.getHeaders().getLocation());
    String entry = resp.parseAsString();
    return RekorResponse.newRekorResponse(rekorEntryUri, entry);
  }

  public Optional<RekorEntry> getEntry(HashedRekordRequest hashedRekordRequest)
      throws IOException, RekorParseException {
    return getEntry(hashedRekordRequest.computeUUID());
  }

  public Optional<RekorEntry> getEntry(String UUID) throws IOException, RekorParseException {
    URI getEntryURI = serverUrl.resolve(REKOR_ENTRIES_PATH + "/" + UUID);
    HttpRequest req =
        HttpClients.newRequestFactory(httpParams).buildGetRequest(new GenericUrl(getEntryURI));
    req.getHeaders().set("Accept", "application/json");
    HttpResponse response;
    try {
      response = req.execute();
    } catch (HttpResponseException e) {
      if (e.getStatusCode() == 404) return Optional.empty();
      throw e;
    }
    return Optional.of(
        RekorResponse.newRekorResponse(getEntryURI, response.parseAsString()).getEntry());
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
      throws IOException, RekorParseException {
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

    String contentString = GSON.get().toJson(data);
    HttpRequest req =
        HttpClients.newRequestFactory(httpParams)
            .buildPostRequest(
                new GenericUrl(rekorSearchEndpoint),
                ByteArrayContent.fromString("application/json", contentString));
    req.getHeaders().set("Accept", "application/json");
    req.getHeaders().set("Content-Type", "application/json");
    var response = req.execute();
    String responseJson = response.parseAsString();
    try {
      return Arrays.asList(GSON.get().fromJson(responseJson, String[].class));
    } catch (JsonSyntaxException e) {
      throw new RekorParseException("Unable to parse output of " + REKOR_INDEX_SEARCH_PATH + ": " + responseJson, e);
    }
  }
}
