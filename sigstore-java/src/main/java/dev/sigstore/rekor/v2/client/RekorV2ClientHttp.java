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
package dev.sigstore.rekor.v2.client;

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.util.Preconditions;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.proto.rekor.v2.CreateEntryRequest;
import dev.sigstore.proto.rekor.v2.DSSERequestV002;
import dev.sigstore.proto.rekor.v2.HashedRekordRequestV002;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.net.URI;
import java.util.Locale;

/** A client to communicate with a rekor v2 service instance over http. */
public class RekorV2ClientHttp implements RekorV2Client {
  public static final String REKOR_ENTRIES_PATH = "/api/v2/log/entries";
  public static final String REKOR_CHECKPOINT_PATH = "/api/v2/checkpoint";

  private final HttpParams httpParams;
  private final URI uri;

  public static RekorV2ClientHttp.Builder builder() {
    return new RekorV2ClientHttp.Builder();
  }

  private RekorV2ClientHttp(HttpParams httpParams, URI uri) {
    this.uri = uri;
    this.httpParams = httpParams;
  }

  public static class Builder {
    private HttpParams httpParams = ImmutableHttpParams.builder().build();
    private Service service;

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams}, {@link ImmutableHttpParams}. */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** Service information for a remote rekor instance. */
    public Builder setService(Service service) {
      this.service = service;
      return this;
    }

    public RekorV2ClientHttp build() {
      Preconditions.checkNotNull(service);
      return new RekorV2ClientHttp(httpParams, service.getUrl());
    }
  }

  @Override
  public RekorEntry putEntry(HashedRekordRequestV002 hashedRekordRequest)
      throws IOException, RekorParseException {
    URI rekorPutEndpoint = uri.resolve(REKOR_ENTRIES_PATH);

    String jsonPayload =
        JsonFormat.printer()
            .print(
                CreateEntryRequest.newBuilder()
                    .setHashedRekordRequestV002(hashedRekordRequest)
                    .build());

    HttpRequest req =
        HttpClients.newRequestFactory(httpParams)
            .buildPostRequest(
                new GenericUrl(rekorPutEndpoint),
                ByteArrayContent.fromString("application/json", jsonPayload));
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

    String respEntryJson = resp.parseAsString();

    return RekorEntry.fromTLogEntryJson(respEntryJson);
  }

  @Override
  public RekorEntry putEntry(DSSERequestV002 dsseRequestV002)
      throws IOException, RekorParseException {
    URI rekorPutEndpoint = uri.resolve(REKOR_ENTRIES_PATH);

    String jsonPayload =
        JsonFormat.printer()
            .print(CreateEntryRequest.newBuilder().setDsseRequestV002(dsseRequestV002).build());

    HttpRequest req =
        HttpClients.newRequestFactory(httpParams)
            .buildPostRequest(
                new GenericUrl(rekorPutEndpoint),
                ByteArrayContent.fromString("application/json", jsonPayload));
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

    String respEntryJson = resp.parseAsString();

    return RekorEntry.fromTLogEntryJson(respEntryJson);
  }
}
