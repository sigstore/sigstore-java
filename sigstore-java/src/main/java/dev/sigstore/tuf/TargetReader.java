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

/** Interface that defines reading targets from local storage. */
public interface TargetReader {

  /**
   * Reads a TUF target file from the local TUF store. Target names may include path elements and
   * the storage engine should be consistent when handling writing and reading these.
   *
   * @param targetName the name of the target file to read (e.g. ctfe.pub)
   * @return the content of the file as bytes
   * @throws IOException if an error occurs
   */
  byte[] readTarget(String targetName) throws IOException;

  /**
   * Checks if the local TUF store actually contains a target file with name.
   *
   * @param targetName the name of the target file to read (e.g. ctfe.pub)
   * @return true if the target exists locally
   * @throws IOException if an error occurs
   */
  boolean hasTarget(String targetName) throws IOException;
}
