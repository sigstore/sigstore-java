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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getDecoder;

import dev.sigstore.json.GsonSupplier;
import dev.sigstore.rekor.Hashedrekord;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/** A local representation of a rekor entry in the log. */
@Gson.TypeAdapters
@Value.Immutable
public interface RekorEntry {

  com.google.gson.Gson GSON = new GsonSupplier().get();

  /** A class representing verification information for a log entry. */
  @Value.Immutable
  interface Verification {
    /** Return the signed entry timestamp. */
    String getSignedEntryTimestamp();
  }

  /** Returns the content of the log entry. */
  String getBody();

  @Value.Derived
  default Hashedrekord getBodyAsHashedrekord() {
    return GSON.fromJson(
            new String(getDecoder().decode(getBody()), UTF_8), HashedRekordWrapper.class)
        .getSpec();
  }

  /** Returns the time the entry was integrated into the log. */
  long getIntegratedTime();

  /**
   * Returns the sha256 of the log's public key. Should be the same for all entries into this log.
   */
  String getLogID();

  /** Returns the index in the log of this entry. */
  long getLogIndex();

  /** Returns the verification material for this entry. */
  Verification getVerification();
}
