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
package dev.sigstore.tuf;

import dev.sigstore.tuf.model.Root;
import java.io.IOException;
import java.util.Optional;

/** Defines the set of actions needed to support a local repository of TUF metadata. */
public interface TufLocalStore {

  /**
   * If the local store has a root that has been blessed safe either by the client or through update
   * and verification, then this method returns it.
   */
  Optional<Root> getTrustedRoot();

  /**
   * Once you have ascertained that your root is trustworthy use this method to persist it to your
   * local store. This will usually only be called with a root loaded statically from a bundled
   * trusted root, or after the successful verification of an updated root from a mirror.
   *
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">5.3.8</a>
   * @param root a root that has been proven trustworthy by the client
   * @throws IOException since some implementations may persist the root to disk or over the network
   *     we throw {@code IOException} in case of IO error.
   */
  void setTrustedRoot(Root root) throws IOException;

  /**
   * This clears out the snapshot and timestamp metadata from the store, as required when snapshot
   * or timestamp verification keys have changed as a result of a root update.
   *
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/#detailed-client-workflow">5.3.11</a>
   * @throws IOException implementations that read/write IO to clear the data may throw {@code
   *     IOException}
   */
  void clearMetaDueToKeyRotation() throws IOException;
}
