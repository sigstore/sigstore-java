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
}
