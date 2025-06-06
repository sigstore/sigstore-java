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
package dev.sigstore.timestamp.client;

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.util.Preconditions;
import com.google.common.annotations.VisibleForTesting;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

/** A client to communicate with a timestamp service instance. */
public class TimestampClientHttp implements TimestampClient {
  private static final String CONTENT_TYPE_TIMESTAMP_QUERY = "application/timestamp-query";
  private static final String ACCEPT_TYPE_TIMESTAMP_REPLY = "application/timestamp-reply";

  private final HttpRequestFactory requestFactory;
  private final URI uri;

  public static TimestampClientHttp.Builder builder() {
    return new TimestampClientHttp.Builder();
  }

  @VisibleForTesting
  TimestampClientHttp(HttpRequestFactory requestFactory, URI uri) {
    this.requestFactory = requestFactory;
    this.uri = uri;
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

    /** Base url of the timestamp authority. */
    public Builder setService(Service service) {
      this.service = service;
      return this;
    }

    public TimestampClientHttp build() throws IOException {
      Preconditions.checkNotNull(service);
      var requestFactory = HttpClients.newRequestFactory(httpParams);
      return new TimestampClientHttp(requestFactory, service.getUrl());
    }
  }

  @Override
  public TimestampResponse timestamp(TimestampRequest tsReq) throws TimestampException {
    TimeStampRequestGenerator bcTsReqGen = new TimeStampRequestGenerator();

    // Prepare and send the timestamp request
    var bcAlgorithmOid = tsReq.getHashAlgorithm().getOid();
    var artifactHashBytes = tsReq.getHash();
    var nonce = tsReq.getNonce();
    bcTsReqGen.setCertReq(tsReq.requestCertificates());
    TimeStampRequest bcTsReq;
    HttpResponse httpTsResp;
    try {
      bcTsReq = bcTsReqGen.generate(bcAlgorithmOid, artifactHashBytes, nonce);
      var requestBytes = bcTsReq.getEncoded();
      httpTsResp = sendTimestampRequest(uri, requestBytes);
    } catch (IOException e) {
      throw new TimestampException("Timestamp request failed: " + e.getMessage(), e);
    }

    // Parse the timestamp response
    TimestampResponse tsResp;
    try {
      var bcTsResp = getBcTimestampResponse(httpTsResp, bcTsReq);
      var tsRespBytes = bcTsResp.getEncoded();
      tsResp = ImmutableTimestampResponse.builder().encoded(tsRespBytes).build();
    } catch (IOException | TSPException e) {
      throw new TimestampException(
          "Timestamp response validation or parsing failed: " + e.getMessage(), e);
    }

    return tsResp;
  }

  HttpResponse sendTimestampRequest(URI tsaUri, byte[] requestBytes) throws IOException {
    Objects.requireNonNull(tsaUri, "tsaUri cannot be null");
    Objects.requireNonNull(requestBytes, "requestBytes cannot be null");
    var httpReq =
        requestFactory.buildPostRequest(
            new GenericUrl(tsaUri),
            new ByteArrayContent(CONTENT_TYPE_TIMESTAMP_QUERY, requestBytes));
    httpReq.getHeaders().setAccept(ACCEPT_TYPE_TIMESTAMP_REPLY);
    httpReq.setThrowExceptionOnExecuteError(false);
    // Skip exception thrown by API to manually handle error code below
    httpReq.setNumberOfRetries(5);
    var httpResp = httpReq.execute();
    if (!(httpResp.getStatusCode() >= 200 && httpResp.getStatusCode() < 300)) {
      throw new IOException(
          String.format(
              Locale.ROOT,
              "bad response from timestamp @ '%s' : %s",
              tsaUri,
              httpResp.parseAsString()));
    }
    return httpResp;
  }

  private TimeStampResponse getBcTimestampResponse(
      HttpResponse httpTsResp, TimeStampRequest bcTsReq) throws IOException, TSPException {
    Objects.requireNonNull(httpTsResp, "HttpResponse cannot be null");
    Objects.requireNonNull(bcTsReq, "TimeStampRequest cannot be null");

    var bcTsResp = new TimeStampResponse(httpTsResp.getContent());
    bcTsResp.validate(bcTsReq);
    return bcTsResp;
  }
}
