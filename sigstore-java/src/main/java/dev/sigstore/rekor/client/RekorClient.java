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

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.common.base.Preconditions;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** A client to communicate with a rekor service instance. */
public class RekorClient {
  public static final String REKOR_ENTRIES_PATH = "/api/v1/log/entries";
  public static final String REKOR_INDEX_SEARCH_PATH = "/api/v1/index/retrieve";

  private final HttpParams httpParams;
  private final TransparencyLog tlog;

  public static RekorClient.Builder builder() {
    return new RekorClient.Builder();
  }

  private RekorClient(HttpParams httpParams, TransparencyLog tlog) {
    this.tlog = tlog;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private HttpParams httpParams = ImmutableHttpParams.builder().build();
    private TransparencyLog tlog;

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}, {@link ImmutableHttpParams}. */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** Configure the remote rekor instance to communicate with. */
    public Builder setTransparencyLog(TransparencyLog tlog) {
      this.tlog = tlog;
      return this;
    }

    /** Configure the remote rekor instance to communicate with, inferred from a trusted root. */
    public Builder setTransparencyLog(SigstoreTrustedRoot trustedRoot) {
      this.tlog = trustedRoot.getTLogs().current();
      return this;
    }

    public RekorClient build() {
      Preconditions.checkNotNull(tlog);
      return new RekorClient(httpParams, tlog);
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
    URI rekorPutEndpoint = tlog.getBaseUrl().resolve(REKOR_ENTRIES_PATH);

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

    URI rekorEntryUri = tlog.getBaseUrl().resolve(resp.getHeaders().getLocation());
    String entry = resp.parseAsString();
    return RekorResponse.newRekorResponse(rekorEntryUri, entry);
  }

  public Optional<RekorEntry> getEntry(HashedRekordRequest hashedRekordRequest)
      throws IOException, RekorParseException {
    return getEntry(hashedRekordRequest.computeUUID());
  }

  public Optional<RekorEntry> getEntry(String UUID) throws IOException, RekorParseException {
    URI getEntryURI = tlog.getBaseUrl().resolve(REKOR_ENTRIES_PATH + "/" + UUID);
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
      throws IOException {
    URI rekorSearchEndpoint = tlog.getBaseUrl().resolve(REKOR_INDEX_SEARCH_PATH);

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
    return Arrays.asList(GSON.get().fromJson(response.parseAsString(), String[].class));
  }
}
