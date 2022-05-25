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

import org.immutables.gson.Gson;
import org.immutables.value.Value;

/** A local representation of a rekor entry in the log. */
@Gson.TypeAdapters
@Value.Immutable
public interface RekorEntry {
  /** A class representing verification information for a log entry. */
  @Value.Immutable
  public interface Verification {
    /** Return the signed entry timestamp. */
    String getSignedEntryTimestamp();
  }

  /** Returns the content of the log entry. */
  String getBody();

  /** Returns the time the entry was integrated into the log. */
  public long getIntegratedTime();

  /**
   * Returns the sha256 of the log's public key. Should be the same for all entries into this log.
   */
  public String getLogID();

  /** Returns the index in the log of this entry. */
  public long getLogIndex();

  /** Returns the verification material for this entry. */
  public Verification getVerification();
}
