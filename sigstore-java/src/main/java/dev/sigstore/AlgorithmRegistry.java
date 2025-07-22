/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore;

import static com.google.common.hash.Hashing.*;

import com.google.common.hash.HashFunction;

public class AlgorithmRegistry {
  public enum SigningAlgorithm {
    PKIX_RSA_PKCS1V15_2048_SHA256(HashAlgorithm.SHA2_256),
    PKIX_RSA_PKCS1V15_3072_SHA256(HashAlgorithm.SHA2_256),
    PKIX_RSA_PKCS1V15_4096_SHA256(HashAlgorithm.SHA2_256),

    // ECDSA
    PKIX_ECDSA_P256_SHA_256(HashAlgorithm.SHA2_256);
    // TODO: PKIX_ECDSA_P384_SHA_384(HashAlgorithm.SHA2_384),
    // TODO: PKIX_ECDSA_P521_SHA_512(HashAlgorithm.SHA2_512);

    private final HashAlgorithm hashAlgorithm;

    SigningAlgorithm(HashAlgorithm hashAlgorithm) {
      this.hashAlgorithm = hashAlgorithm;
    }

    public HashAlgorithm getHashing() {
      return hashAlgorithm;
    }
  }

  public enum HashAlgorithm {
    SHA2_256("SHA256", 32, sha256());
    // TODO: SHA2_384("SHA384", 48, sha384()),
    // TODO: SHA2_512("SHA512", 64, sha512());

    private final String name;
    private final int length;
    private final HashFunction hashFunction;

    HashAlgorithm(String name, int length, HashFunction hashFunction) {
      this.name = name;
      this.length = length;
      this.hashFunction = hashFunction;
    }

    public String toString() {
      return name;
    }

    public int getLength() {
      return length;
    }

    HashFunction getHashFunction() {
      return hashFunction;
    }
  }
}
