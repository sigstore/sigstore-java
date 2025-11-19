/*
 * Copyright 2023 The Sigstore Authors.
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

import dev.sigstore.json.JsonParseException;
import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.RootRole;
import dev.sigstore.tuf.model.SignedTufMeta;
import dev.sigstore.tuf.model.Snapshot;
import dev.sigstore.tuf.model.Targets;
import dev.sigstore.tuf.model.Timestamp;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;
import java.util.Optional;

/** Local storage for local state of TUF metadata. */
public class TrustedMetaStore {

  private final MetaStore metaStore;

  private TrustedMetaStore(MetaStore metaStore) {
    this.metaStore = metaStore;
  }

  public static TrustedMetaStore newTrustedMetaStore(MetaStore metaStore) {
    return new TrustedMetaStore(metaStore);
  }

  /**
   * A generic string for identifying the local store in debug messages. A file system based
   * implementation might return the path being used for storage, while an in-memory store may just
   * return something like 'in-memory'.
   */
  public String getIdentifier() {
    return metaStore.getIdentifier();
  }

  /**
   * Return a named metadata item. Fail if there isn't any
   *
   * @param roleName the name of the role to load (root, timestamp, snapshot, targets, or a
   *     delegated target role)
   * @param tClass the class type
   * @return an instance of the signed metadata for the role if it was found
   * @throws IOException if an error occurs reading from the backing store
   * @throws IllegalStateException if the data was never persisted and this function was called
   */
  <T extends SignedTufMeta<? extends TufMeta>> T getMeta(String roleName, Class<T> tClass)
      throws IOException, JsonParseException {
    return metaStore
        .readMeta(roleName, tClass)
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "No cached "
                        + roleName
                        + " to load. This error may occur when (1) update hasn't been called or (2) when find should have been used instead of get."));
  }

  public void setRoot(Root root) throws IOException {
    metaStore.writeMeta(RootRole.ROOT, root);
  }

  public Root getRoot() throws IOException, JsonParseException {
    return getMeta(RootRole.ROOT, Root.class);
  }

  public Optional<Root> findRoot() throws IOException, JsonParseException {
    return metaStore.readMeta(RootRole.ROOT, Root.class);
  }

  public void setTimestamp(Timestamp timestamp) throws IOException {
    metaStore.writeMeta(RootRole.TIMESTAMP, timestamp);
  }

  public Timestamp getTimestamp() throws IOException, JsonParseException {
    return getMeta(RootRole.TIMESTAMP, Timestamp.class);
  }

  public Optional<Timestamp> findTimestamp() throws IOException, JsonParseException {
    return metaStore.readMeta(RootRole.TIMESTAMP, Timestamp.class);
  }

  public void setSnapshot(Snapshot snapshot) throws IOException {
    metaStore.writeMeta(RootRole.SNAPSHOT, snapshot);
  }

  public Snapshot getSnapshot() throws IOException, JsonParseException {
    return getMeta(RootRole.SNAPSHOT, Snapshot.class);
  }

  public Optional<Snapshot> findSnapshot() throws IOException, JsonParseException {
    return metaStore.readMeta(RootRole.SNAPSHOT, Snapshot.class);
  }

  public void setTargets(Targets targets) throws IOException {
    metaStore.writeMeta(RootRole.TARGETS, targets);
  }

  public Targets getTargets() throws IOException, JsonParseException {
    return getMeta(RootRole.TARGETS, Targets.class);
  }

  public Optional<Targets> findTargets() throws IOException, JsonParseException {
    return metaStore.readMeta(RootRole.TARGETS, Targets.class);
  }

  public void clearMetaDueToKeyRotation() throws IOException {
    metaStore.clearMeta(RootRole.TIMESTAMP);
    metaStore.clearMeta(RootRole.SNAPSHOT);
  }
}
