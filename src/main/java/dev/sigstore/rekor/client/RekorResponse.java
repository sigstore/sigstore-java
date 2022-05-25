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

import com.google.common.reflect.TypeToken;
import com.google.gson.GsonBuilder;
import java.net.URI;
import java.util.Map;
import org.immutables.value.Value;

/**
 * Representation of a rekor response with the log location, raw log string and parsed log
 * information.
 */
@Value.Immutable
public interface RekorResponse {

  /**
   * Create a RekorResponse from raw http response information.
   *
   * <p>A raw http response looks something like:
   *
   * <pre>
   * {
   *   "dbf7b3f960d0d5853f80dfc968779554a628b44a30a4c8a2084b5bd2f6970085": {  // log uuid
   *     "body": "eyJhcGlWZX...UzBLIn19fX0=",
   *     "integratedTime": 1653410800,
   *     "logID": "d32f30a3...18723a1bea496",
   *     "logIndex": 52,
   *     "verification": {
   *      "signedEntryTimestamp": "MEYCIQCYufGO...Oc9UAqVb+dCCl"
   *     }
   *   }
   * }
   * </pre>
   *
   * @param entryLocation the entry location from the http headers
   * @param rawResponse the body of the rekor response as a string
   * @return an immutable {@link RekorResponse} instance
   */
  static RekorResponse newRekorResponse(URI entryLocation, String rawResponse) {
    var gson = new GsonBuilder().registerTypeAdapterFactory(new GsonAdaptersRekorEntry()).create();
    var type = new TypeToken<Map<String, RekorEntry>>() {}.getType();
    Map<String, RekorEntry> entryMap = gson.fromJson(rawResponse, type);
    if (entryMap.size() != 1) {
      throw new IllegalArgumentException(
          "Expecting a single rekor entry in response but found: " + entryMap.size());
    }
    var entry = entryMap.entrySet().iterator().next();
    return ImmutableRekorResponse.builder()
        .entryLocation(entryLocation)
        .raw(rawResponse)
        .uuid(entry.getKey())
        .entry(entry.getValue())
        .build();
  }

  /** Path to the rekor entry on the log. */
  public URI getEntryLocation();

  /** Returns the {@link RekorEntry} representation of the entry on the log. */
  public RekorEntry getEntry();

  /** Returns the log uuid of entry represented by {@link #getEntry()}. */
  public String getUuid();

  /** Returns the raw response from the rekor request. */
  public String getRaw();
}
