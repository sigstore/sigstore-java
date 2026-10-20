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

import dev.sigstore.tuf.model.SignedTufMeta;

/**
 * Result object returned by {@link MetaFetcher} interface.
 *
 * @param <T> a TUF signed resource role
 */
public class MetaFetchResult<T extends SignedTufMeta> {
  private byte[] rawBytes;
  private T metaResource;

  public MetaFetchResult(byte[] rawBytes, T metaResource) {
    this.rawBytes = rawBytes;
    this.metaResource = metaResource;
  }

  /** The resources raw bytes received from the mirror. */
  public byte[] getRawBytes() {
    return rawBytes;
  }

  /** The hydrated object from the bytestrema. */
  public T getMetaResource() {
    return metaResource;
  }
}
