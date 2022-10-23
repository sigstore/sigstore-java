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
 * To prevent an adversary from replaying an out-of-date signed metadata file whose signature has
 * not yet expired, an automated process periodically signs a timestamped statement containing the
 * hash of the snapshot file. Even though this timestamp key must be kept online, the risk posed to
 * clients by the compromise of this key is minimal.
 */
@Gson.TypeAdapters
@Value.Immutable
public interface TimestampMeta extends TufMeta {

  /** Will only contain one element called snapshot.json */
  Map<String, SnapshotMeta.SnapshotTarget> getMeta();
}
