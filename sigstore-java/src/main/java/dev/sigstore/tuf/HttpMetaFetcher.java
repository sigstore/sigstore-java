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
package dev.sigstore.tuf;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.json.gson.GsonFactory;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.tuf.model.Role;
import dev.sigstore.tuf.model.Root;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class HttpMetaFetcher implements MetaFetcher {

  private static final int MAX_META_BYTES = 99 * 1024; // 99 KB
  private URL mirror;

  HttpMetaFetcher(URL mirror) {
    this.mirror = mirror;
  }

  public static HttpMetaFetcher newFetcher(URL mirror) {
    return new HttpMetaFetcher(mirror);
  }

  @Override
  public String getSource() {
    return mirror.toString();
  }

  @Override
  public Optional<Root> getRootAtVersion(int version)
      throws IOException, MetaFileExceedsMaxException {
    String versionFileName = version + ".root.json";
    return getMeta(versionFileName, Root.class);
  }

  @Override
  public <T> Optional<T> getMeta(Role.Name role, Class<T> t) throws IOException, MetaFileExceedsMaxException {
    String fileName = role.name().toLowerCase() + ".json";
    return getMeta(fileName, t);
  }

  <T> Optional<T> getMeta(String filename, Class<T> t) throws IOException, MetaFileExceedsMaxException {
    GenericUrl nextVersionUrl = new GenericUrl(mirror + "/" + filename);
    var req =
      HttpClients.newHttpTransport(ImmutableHttpParams.builder().build())
        .createRequestFactory(
          request -> {
            request.setParser(GsonFactory.getDefaultInstance().createJsonObjectParser());
          })
        .buildGetRequest(nextVersionUrl);
    req.getHeaders().setAccept("application/json; api-version=2.0");
    req.getHeaders().setContentType("application/json");
    req.setThrowExceptionOnExecuteError(false);
    var resp = req.execute();
    if (resp.getStatusCode() == 404) {
      return Optional.empty();
    }
    if (resp.getStatusCode() != 200) {
      throw new TufException(
        String.format(
          "Unexpected return from mirror. Status code: %s, status message: %s"
            + resp.getStatusCode()
            + resp.getStatusMessage()));
    }
    byte[] roleBytes = resp.getContent().readNBytes(MAX_META_BYTES);
    if (roleBytes.length == MAX_META_BYTES && resp.getContent().read() != -1) {
      throw new MetaFileExceedsMaxException(nextVersionUrl.toString(), MAX_META_BYTES);
    }
    return Optional.of(
      GSON.get().fromJson(new String(roleBytes, StandardCharsets.UTF_8), t));
  }

}
