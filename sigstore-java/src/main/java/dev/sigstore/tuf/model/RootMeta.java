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
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/**
 * Specifies the other top-level roles. When specifying these roles, the trusted keys for each are
 * listed, along with the minimum number of those keys required to sign the role's metadata. We call
 * this number the signature threshold.
 *
 * @see <a href="https://theupdateframework.io/metadata/#root-metadata-rootjson">TUF Root
 *     documentation</a>
 */
@Gson.TypeAdapters
@Value.Immutable
public interface RootMeta extends TufMeta {

  /**
   * Typically {@code false} and unused for Sigstore TUF.
   *
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/#consistent-snapshots">TUF
   *     docs</a>
   */
  @Gson.Named("consistent_snapshot")
  boolean getConsistentSnapshot();

  /**
   * Map of Key IDs to {@link Key}.
   *
   * @see <a href="https://theupdateframework.github.io/specification/latest/#file-formats-root">TUF
   *     KEYID doc</a>
   */
  Map<String, Key> getKeys();

  /**
   * A map from role name to <a
   * href="https://theupdateframework.io/metadata/#root-metadata-rootjson">role</a>.
   */
  Map<String, RootRole> getRoles();

  default RootRole getRole(Role.Name name) {
    return getRoles().get(name.toString());
  }
}
