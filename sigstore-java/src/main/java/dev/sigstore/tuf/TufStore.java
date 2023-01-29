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

import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.Snapshot;
import dev.sigstore.tuf.model.Targets;
import dev.sigstore.tuf.model.Timestamp;
import java.io.IOException;
import java.util.Optional;

public interface TufStore {
  /**
   * A generic string for identifying the local store in debug messages. A file system based
   * implementation might return the path being used for storage, while an in-memory store may just
   * return something like 'in-memory'.
   */
  String getIdentifier();

  /** Local store must have a root that has been blessed safe. */
  Optional<Root> loadTrustedRoot() throws IOException;

  /** Return local trusted timestamp metadata if there is any. */
  Optional<Timestamp> loadTimestamp() throws IOException;

  /** Return the local trusted snapshot metadata if there is any. */
  Optional<Snapshot> loadSnapshot() throws IOException;

  /** Return the local trusted targets metadata if there is any. */
  Optional<Targets> loadTargets() throws IOException;

  /**
   * Reads a TUF target file from the local TUF store
   *
   * @param targetName the name of the target file to read (e.g. ctfe.pub)
   * @return the content of the file as bytes
   * @throws IOException if an error occurs
   */
  byte[] getTargetFile(String targetName) throws IOException;
}
