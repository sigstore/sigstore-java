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

import com.google.gson.JsonElement;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/**
 * A representation of the body of a {@link RekorEntry}. The "spec" remains unparsed and should be
 * parsed into specific types after inspecting kind and apiVersion. Format example. e.g.
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
public interface RekorEntryBody {

  String getApiVersion();

  String getKind();

  /**
   * Returns spec as an unparsed JsonElement. It should parsed after verifying kind and apiVersion.
   * See {@link RekorTypes}.
   */
  JsonElement getSpec();
}
