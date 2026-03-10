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

import com.google.common.base.Preconditions;
import dev.sigstore.json.JsonParseException;
import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.SignedTufMeta;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;
import javax.annotation.Nullable;

public class MetaFetcher {

  private static final int MAX_META_BYTES = 99 * 1024; // 99 KB
  private final Fetcher fetcher;

  private MetaFetcher(Fetcher fetcher) {
    this.fetcher = fetcher;
  }

  public static MetaFetcher newFetcher(Fetcher fetcher) {
    return new MetaFetcher(fetcher);
  }

  public String getSource() {
    return fetcher.getSource();
  }

  public Optional<MetaFetchResult<Root>> getRootAtVersion(int version)
      throws IOException, FileExceedsMaxLengthException, JsonParseException {
    String versionFileName = version + ".root.json";
    return getMeta(versionFileName, Root.class, null);
  }

  public <T extends SignedTufMeta<? extends TufMeta>> Optional<MetaFetchResult<T>> getMeta(
      String role, Class<T> t)
      throws IOException, FileExceedsMaxLengthException, JsonParseException {
    return getMeta(getFileName(role, null), t, null);
  }

  public <T extends SignedTufMeta<? extends TufMeta>> Optional<MetaFetchResult<T>> getMeta(
      String role, int version, Class<T> t, Integer maxSize)
      throws IOException, FileExceedsMaxLengthException, JsonParseException {
    Preconditions.checkArgument(version > 0, "version should be positive, got: %s", version);
    return getMeta(getFileName(role, version), t, maxSize);
  }

  private static String getFileName(String role, @Nullable Integer version) {
    String encodedRole = TufNames.encode(role);
    return version == null
        ? encodedRole + ".json"
        : String.format(Locale.ROOT, "%d.%s.json", version, encodedRole);
  }

  <T extends SignedTufMeta<? extends TufMeta>> Optional<MetaFetchResult<T>> getMeta(
      String filename, Class<T> t, Integer maxSize)
      throws IOException, FileExceedsMaxLengthException, JsonParseException {
    byte[] roleBytes = fetcher.fetchResource(filename, maxSize == null ? MAX_META_BYTES : maxSize);
    if (roleBytes == null) {
      return Optional.empty();
    }
    var result =
        new MetaFetchResult<T>(
            roleBytes, GSON.get().fromJson(new String(roleBytes, StandardCharsets.UTF_8), t));
    return Optional.of(result);
  }
}
