/*
 * Copyright 2024 The Sigstore Authors.
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

import dev.sigstore.tuf.model.SignedTufMeta;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** An in memory cache that will pass through to a provided local tuf store. */
public class PassthroughCacheMetaStore implements MetaReader, MetaStore {
  private final MetaStore localStore;
  private final Map<String, SignedTufMeta<? extends TufMeta>> cache;

  private PassthroughCacheMetaStore(MetaStore localStore) {
    this.localStore = localStore;
    this.cache = new HashMap<>();
  }

  @Override
  public String getIdentifier() {
    return "In memory cache backed by: " + localStore.getIdentifier();
  }

  public static PassthroughCacheMetaStore newPassthroughMetaCache(MetaStore localStore) {
    return new PassthroughCacheMetaStore(localStore);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T extends SignedTufMeta<? extends TufMeta>> Optional<T> readMeta(
      String roleName, Class<T> tClass) throws IOException {
    // check memory cache
    if (cache.containsKey(roleName)) {
      return Optional.of((T) cache.get(roleName));
    }

    // check backing storage and write to memory if found
    var value = localStore.readMeta(roleName, tClass);
    value.ifPresent(v -> cache.put(roleName, v));

    return value;
  }

  @Override
  public void writeMeta(String roleName, SignedTufMeta<? extends TufMeta> meta) throws IOException {
    localStore.writeMeta(roleName, meta);
    cache.put(roleName, meta);
  }

  @Override
  public void clearMeta(String role) throws IOException {
    localStore.clearMeta(role);
    cache.remove(role);
  }
}
