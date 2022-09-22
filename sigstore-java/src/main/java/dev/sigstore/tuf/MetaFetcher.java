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

import dev.sigstore.tuf.model.Role;
import dev.sigstore.tuf.model.Root;
import java.io.IOException;
import java.util.Optional;

/** Retrieves TUF metadata. */
public interface MetaFetcher {

  /**
   * Describes the source of the metadata being fetched from. e.g "http://mirror.bla/mirror",
   * "mock", "c:/tmp".
   */
  String getSource();

  /**
   * Fetch the {@link Root} at the specified {@code version}.
   *
   * @throws MetaFileExceedsMaxException when the retrieved file is larger than the maximum allowed
   *     by the client
   */
  Optional<Root> getRootAtVersion(int version) throws IOException, MetaFileExceedsMaxException;

  /**
   * Fetches the specified role meta from the source
   *
   * @param name TUF role name
   * @param roleType this should be the type you expect in return
   * @return the fully de-serialized role if it was present at the source
   * @throws IOException in case of IO errors
   * @throws MetaFileExceedsMaxException if the role meta at source exceeds client specified max
   *     size
   */
  <T> Optional<T> getMeta(Role.Name name, Class<T> roleType)
      throws IOException, MetaFileExceedsMaxException;
}
