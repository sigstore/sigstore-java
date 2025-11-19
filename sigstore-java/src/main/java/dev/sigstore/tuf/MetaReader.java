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

import dev.sigstore.json.JsonParseException;
import dev.sigstore.tuf.model.SignedTufMeta;
import dev.sigstore.tuf.model.TufMeta;
import java.io.IOException;
import java.util.Optional;

/** Interface that defines reading meta from local storage. */
public interface MetaReader {

  /**
   * Return a named metadata item if there is any.
   *
   * @param roleName the name of the role to load (root, timestamp, snapshot, targets, or a
   *     delegated target role)
   * @param tClass the class type
   * @return an instance of the signed metadata for the role if it was found
   * @throws IOException if an error occurs reading from the backing store
   */
  <T extends SignedTufMeta<? extends TufMeta>> Optional<T> readMeta(
      String roleName, Class<T> tClass) throws IOException, JsonParseException;
}
