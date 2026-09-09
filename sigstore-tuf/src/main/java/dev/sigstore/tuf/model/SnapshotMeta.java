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
package dev.sigstore.tuf.model;

import java.util.Map;
import java.util.Optional;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;

/**
 * The snapshot.json metadata file lists version numbers of all metadata files other than
 * timestamp.json. This file ensures that clients will see a consistent view of all files on the
 * repository. That is, metadata files (and thus Target files) that existed on the repository at
 * different times cannot be combined and presented to clients by an attacker.
 */
@Gson.TypeAdapters
@Value.Immutable
public interface SnapshotMeta extends TufMeta {

  /**
   * If no length is provided, use a default, we just use the same default as the python client:
   * https://github.com/theupdateframework/python-tuf/blob/22080157f438357935bfcb25b5b8429f4e4f610e/tuf/ngclient/config.py#L49
   */
  Integer DEFAULT_MAX_LENGTH = 2000000;

  /** Maps role and delegation role names (e.g. "targets.json") to snapshot metadata. */
  Map<String, SnapshotTarget> getMeta();

  default SnapshotTarget getTargetMeta(String targetName) {
    return getMeta().get(targetName);
  }

  /** Snapshot data to prevent mix and match attacks. */
  @Value.Immutable
  interface SnapshotTarget {

    /** The valid hashes for the given target's metadata. This is optional and may not be present */
    Optional<Hashes> getHashes();

    /**
     * The length in bytes of the given target's metadata. This is optional and may not be present,
     * use {@link #getLengthOrDefault} to delegate to the client default config.
     */
    Optional<Integer> getLength();

    /** The length in bytes of the given target's metadata, or a default if not present */
    @Derived
    @Gson.Ignore
    default Integer getLengthOrDefault() {
      return getLength().orElse(DEFAULT_MAX_LENGTH);
    }

    /** The expected version of the given target's metadata. */
    int getVersion();
  }
}
