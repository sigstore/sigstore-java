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

import dev.sigstore.rekor.HashedRekord;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/**
 * Used go get GSON to deserialize {@code Hashedrekor} correctly since Rekor returns it wrapped in
 * resource def format. e.g.
 *
 * <pre>
 * {
 *   "apiVersion": "0.0.1",
 *   "kind": "hashedrekord",
 *   "spec": {
 *     "data": {
 *       "hash": {
 *         "algorithm": "sha256",
 *         "value": "..."
 *       }
 *     },
 *     "signature": {
 *       "content": "...",
 *       "publicKey": {
 *         "content": ".."
 *       }
 *     }
 *   }
 * }
 * </pre>
 */
@Gson.TypeAdapters
@Value.Immutable
public interface HashedRekordWrapper {

  HashedRekord getSpec();
}
