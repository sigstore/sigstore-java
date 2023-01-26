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
import dev.sigstore.tuf.model.SignedTufMeta;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public class HttpMetaFetcher implements MetaFetcher {

  private static final int MAX_META_BYTES = 99 * 1024; // 99 KB
  private final URL mirror;

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
  public Optional<MetaFetchResult<Root>> getRootAtVersion(int version)
      throws IOException, FileExceedsMaxLengthException {
    String versionFileName = version + ".root.json";
    return getMeta(versionFileName, Root.class, null);
  }

  @Override
  public <T extends SignedTufMeta> Optional<MetaFetchResult<T>> getMeta(Role.Name role, Class<T> t)
      throws IOException, FileExceedsMaxLengthException {
    return getMeta(role, t, null);
  }

  @Override
  public <T extends SignedTufMeta> Optional<MetaFetchResult<T>> getMeta(
      Role.Name role, Class<T> t, Integer maxSize)
      throws IOException, FileExceedsMaxLengthException {
    String fileName = role.name().toLowerCase(Locale.ROOT) + ".json";
    return getMeta(fileName, t, maxSize);
  }

  <T extends SignedTufMeta> Optional<MetaFetchResult<T>> getMeta(
      String filename, Class<T> t, Integer maxSize)
      throws IOException, FileExceedsMaxLengthException {
    byte[] roleBytes = fetchResource(filename, maxSize == null ? MAX_META_BYTES : maxSize);
    if (roleBytes == null) {
      return Optional.empty();
    }
    var result =
        new MetaFetchResult<T>(
            roleBytes, GSON.get().fromJson(new String(roleBytes, StandardCharsets.UTF_8), t));
    return Optional.of(result);
  }

  @Override
  public byte[] fetchResource(String filename, int maxLength)
      throws IOException, FileExceedsMaxLengthException {
    GenericUrl fileUrl = new GenericUrl(mirror + "/" + filename);
    var req =
        HttpClients.newHttpTransport(ImmutableHttpParams.builder().build())
            .createRequestFactory(
                request ->
                    request.setParser(GsonFactory.getDefaultInstance().createJsonObjectParser()))
            .buildGetRequest(fileUrl);
    req.getHeaders().setAccept("application/json; api-version=2.0");
    req.getHeaders().setContentType("application/json");
    req.setThrowExceptionOnExecuteError(false);
    var resp = req.execute();
    if (resp.getStatusCode() == 404) {
      return null;
    }
    if (resp.getStatusCode() != 200) {
      throw new TufException(
          String.format(
              Locale.ROOT,
              "Unexpected return from mirror(%s). Status code: %s, status message: %s",
              mirror,
              resp.getStatusCode(),
              resp.getStatusMessage()));
    }
    byte[] roleBytes = resp.getContent().readNBytes(maxLength);
    if (roleBytes.length == maxLength && resp.getContent().read() != -1) {
      throw new FileExceedsMaxLengthException(fileUrl.toString(), maxLength);
    }
    return roleBytes;
  }
}
