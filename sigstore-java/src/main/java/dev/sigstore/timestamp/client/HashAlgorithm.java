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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/** Supported hash algorithms for timestamp requests. */
public enum HashAlgorithm {
  SHA256("SHA256", TSPAlgorithms.SHA256),
  SHA384("SHA384", TSPAlgorithms.SHA384),
  SHA512("SHA512", TSPAlgorithms.SHA512);

  private final String algorithmName;
  private final ASN1ObjectIdentifier oid;

  HashAlgorithm(String algorithmName, ASN1ObjectIdentifier oid) {
    this.algorithmName = algorithmName;
    this.oid = oid;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public static HashAlgorithm from(ASN1ObjectIdentifier oid)
      throws UnsupportedHashAlgorithmException {
    for (HashAlgorithm value : values()) {
      if (value.getOid().equals(oid)) {
        return value;
      }
    }
    throw new UnsupportedHashAlgorithmException(oid.getId());
  }

  // this is just temporary to avoid messing with the timestamp package too much while we
  // transition, this enum
  // should really just be using AlgorithmRegistry as much as possible
  public static HashAlgorithm from(AlgorithmRegistry.HashAlgorithm hashAlgorithm) {
    switch (hashAlgorithm) {
      case SHA2_256:
        return SHA256;
      case SHA2_384:
        return SHA384;
      case SHA2_512:
        return SHA512;
    }
    throw new IllegalArgumentException();
  }
}
