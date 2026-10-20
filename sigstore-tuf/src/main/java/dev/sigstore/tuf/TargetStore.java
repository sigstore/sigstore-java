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

import java.io.IOException;

/** Interface that defines a mutable target store functionality. */
public interface TargetStore extends TargetReader {

  /**
   * A generic string for identifying the local store in debug messages. A file system based
   * implementation might return the path being used for storage, while an in-memory store may just
   * return something like 'in-memory'.
   */
  String getIdentifier();

  /**
   * Writes a TUF target to the local target store. Target names may include path elements and the
   * storage engine should be consistent when handling writing and reading these.
   *
   * @param targetName the name of the target file to write (e.g. ctfe.pub)
   * @param targetContents the content of the target file as bytes
   * @throws IOException if an error occurs
   */
  void writeTarget(String targetName, byte[] targetContents) throws IOException;
}
