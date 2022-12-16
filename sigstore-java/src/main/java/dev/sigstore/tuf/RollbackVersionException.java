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

/** Thrown when the version of the latest downloaded role does not match the expectation. */
public class RollbackVersionException extends TufException {
  private int currentVersion;
  private int foundVersion;

  public RollbackVersionException(int currentVersion, int foundVersion) {
    super(
        String.format(
            "Expected version %d or higher but found version %d", currentVersion, foundVersion));
    this.currentVersion = currentVersion;
    this.foundVersion = foundVersion;
  }

  public int getCurrentVersion() {
    return currentVersion;
  }

  public int getFoundVersion() {
    return foundVersion;
  }
}
