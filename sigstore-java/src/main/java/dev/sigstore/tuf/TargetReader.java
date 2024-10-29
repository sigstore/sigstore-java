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

public interface TargetReader {

  /**
   * Reads a TUF target file from the local TUF store
   *
   * @param targetName the name of the target file to read (e.g. ctfe.pub)
   * @return the content of the file as bytes
   * @throws IOException if an error occurs
   */
  byte[] readTarget(String targetName) throws IOException;
}
