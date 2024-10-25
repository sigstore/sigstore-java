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

import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.RootRole;
import dev.sigstore.tuf.model.Snapshot;
import dev.sigstore.tuf.model.Targets;
import dev.sigstore.tuf.model.Timestamp;
import java.io.IOException;
import java.util.Optional;

// An in memory cache that will pass through to a provided local tuf store
class TrustedMeta {
  private final MutableTufStore localStore;
  private Root root;
  private Snapshot snapshot;
  private Timestamp timestamp;
  private Targets targets;

  private TrustedMeta(MutableTufStore localStore) {
    this.localStore = localStore;
  }

  static TrustedMeta newTrustedMeta(MutableTufStore localStore) {
    return new TrustedMeta(localStore);
  }

  public void setRoot(Root root) throws IOException {
    // call storeTrustedRoot instead of generic storeMeta because it does doesn't extra work
    localStore.storeTrustedRoot(root);
    this.root = root;
  }

  public Root getRoot() throws IOException {
    return findRoot().orElseThrow(() -> new IllegalStateException("No cached root to load"));
  }

  public Optional<Root> findRoot() throws IOException {
    if (root == null) {
      root = localStore.loadTrustedRoot().orElse(null);
    }
    return Optional.ofNullable(root);
  }

  public void setTimestamp(Timestamp timestamp) throws IOException {
    localStore.storeMeta(RootRole.TIMESTAMP, timestamp);
    this.timestamp = timestamp;
  }

  public Timestamp getTimestamp() throws IOException {
    return findTimestamp()
        .orElseThrow(() -> new IllegalStateException("No cached timestamp to load"));
  }

  public Optional<Timestamp> findTimestamp() throws IOException {
    if (timestamp == null) {
      timestamp = localStore.loadTimestamp().orElse(null);
    }
    return Optional.ofNullable(timestamp);
  }

  public void setSnapshot(Snapshot snapshot) throws IOException {
    localStore.storeMeta(RootRole.SNAPSHOT, snapshot);
    this.snapshot = snapshot;
  }

  public Snapshot getSnapshot() throws IOException {
    return findSnapshot()
        .orElseThrow(() -> new IllegalStateException("No cached snapshot to load"));
  }

  public Optional<Snapshot> findSnapshot() throws IOException {
    if (snapshot == null) {
      snapshot = localStore.loadSnapshot().orElse(null);
    }
    return Optional.ofNullable(snapshot);
  }

  public void setTargets(Targets targets) throws IOException {
    localStore.storeMeta(RootRole.TARGETS, targets);
    this.targets = targets;
  }

  public Targets getTargets() throws IOException {
    return findTargets().orElseThrow(() -> new IllegalStateException("No cached targets to load"));
  }

  public Optional<Targets> findTargets() throws IOException {
    if (targets == null) {
      targets = localStore.loadTargets().orElse(null);
    }
    return Optional.ofNullable(targets);
  }

  public void clearMetaDueToKeyRotation() throws IOException {
    localStore.clearMetaDueToKeyRotation();
    timestamp = null;
    snapshot = null;
  }
}
