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

/** Thrown when a hash check fails for a given resource. */
public class InvalidHashesException extends TufException {
  static class InvalidHash {
    String algorithm;
    String expectedHash;
    String computedHash;

    InvalidHash(String algorithm, String expectedHash, String computedHash) {
      this.algorithm = algorithm;
      this.expectedHash = expectedHash;
      this.computedHash = computedHash;
    }

    @Override
    public String toString() {
      return String.format(
          "algorithm: %s, expected hash: %s, computed hash: %s",
          algorithm, expectedHash, computedHash);
    }
  }

  InvalidHashesException(
      String resourceName, String algorithm, String expectedHash, String computedHash) {
    this(resourceName, new InvalidHash(algorithm, expectedHash, computedHash));
  }

  InvalidHashesException(String resourceName, InvalidHash... invalidHashes) {
    super(
        String.format(
            "The hashes for %s did not match expectations:\n%s",
            resourceName, invalidHashesToString(invalidHashes)));
  }

  private static String invalidHashesToString(InvalidHash... invalidHashes) {
    StringBuilder stringBuilder = new StringBuilder();
    for (InvalidHash invalidHash : invalidHashes) {
      stringBuilder.append(invalidHash);
      stringBuilder.append('\n');
    }
    return stringBuilder.toString();
  }
}
