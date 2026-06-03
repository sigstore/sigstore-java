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
package dev.sigstore.timestamp.client;

import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.UnsupportedAlgorithmException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/** Supported hash algorithms for timestamp requests. */
public class HashAlgorithm {
  private HashAlgorithm() {}

  public static ASN1ObjectIdentifier toOid(AlgorithmRegistry.HashAlgorithm hashAlgorithm) {
    switch (hashAlgorithm) {
      case SHA2_256:
        return TSPAlgorithms.SHA256;
      case SHA2_384:
        return TSPAlgorithms.SHA384;
      case SHA2_512:
        return TSPAlgorithms.SHA512;
    }
    throw new IllegalArgumentException();
  }

  public static AlgorithmRegistry.HashAlgorithm fromOid(ASN1ObjectIdentifier oid)
      throws UnsupportedAlgorithmException {
    if (oid.equals(TSPAlgorithms.SHA256)) {
      return AlgorithmRegistry.HashAlgorithm.SHA2_256;
    }
    if (oid.equals(TSPAlgorithms.SHA384)) {
      return AlgorithmRegistry.HashAlgorithm.SHA2_384;
    }
    if (oid.equals(TSPAlgorithms.SHA512)) {
      return AlgorithmRegistry.HashAlgorithm.SHA2_512;
    }
    throw new UnsupportedAlgorithmException(
        "Unsupported timestamp hashing algorithm oid: " + oid.getId());
  }
}
