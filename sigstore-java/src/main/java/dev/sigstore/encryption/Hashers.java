/*
 * Copyright 2026 The Sigstore Authors.
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
package dev.sigstore.encryption;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import dev.sigstore.AlgorithmRegistry;

public class Hashers {
  public static HashFunction from(AlgorithmRegistry.HashAlgorithm hashAlgorithm) {
    switch (hashAlgorithm) {
      case SHA2_256:
        return Hashing.sha256();
      case SHA2_384:
        return Hashing.sha384();
      case SHA2_512:
        return Hashing.sha512();
    }
    throw new IllegalStateException();
  }

  public static HashFunction from(AlgorithmRegistry.SigningAlgorithm signingAlgorithm) {
    return from(signingAlgorithm.getHashAlgorithm());
  }
}
