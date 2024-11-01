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
import dev.sigstore.tuf.model.SignedTufMeta;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;

/** Interface that defines a mutable meta store functionality. */
public interface MetaStore extends MetaReader {

  /**
   * A generic string for identifying the local store in debug messages. A file system based
   * implementation might return the path being used for storage, while an in-memory store may just
   * return something like 'in-memory'.
   */
  String getIdentifier();

  /**
   * Generic method to store one of the {@link SignedTufMeta} resources in the local tuf store. Do
   * not use for Root role, use {@link #writeRoot(Root)} instead.
   *
   * @param roleName the name of the role
   * @param meta the metadata to store
   * @throws IOException if writing the resource causes an IO error
   */
  void writeMeta(String roleName, SignedTufMeta<? extends TufMeta> meta) throws IOException;

  /**
   * Once you have ascertained that your root is trustworthy use this method to persist it to your
   * local store. This will usually only be called with a root loaded statically from a bundled
   * trusted root, or after the successful verification of an updated root from a mirror.
   *
   * @param root a root that has been proven trustworthy by the client
   * @throws IOException since some implementations may persist the root to disk or over the network
   *     we throw {@code IOException} in case of IO error.
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">5.3.8</a>
   */
  void writeRoot(Root root) throws IOException;

  /**
   * This clears out the snapshot and timestamp metadata from the store, as required when snapshot
   * or timestamp verification keys have changed as a result of a root update.
   *
   * @throws IOException implementations that read/write IO to clear the data may throw {@code
   *     IOException}
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">5.3.11</a>
   */
  void clearMetaDueToKeyRotation() throws IOException;
}