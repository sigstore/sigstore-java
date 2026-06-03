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
package dev.sigstore.timestamp.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.UnsupportedAlgorithmException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.junit.jupiter.api.Test;

public class HashAlgorithmTest {

  @Test
  public void toOid_success() {
    assertEquals(
        TSPAlgorithms.SHA256, HashAlgorithm.toOid(AlgorithmRegistry.HashAlgorithm.SHA2_256));
    assertEquals(
        TSPAlgorithms.SHA384, HashAlgorithm.toOid(AlgorithmRegistry.HashAlgorithm.SHA2_384));
    assertEquals(
        TSPAlgorithms.SHA512, HashAlgorithm.toOid(AlgorithmRegistry.HashAlgorithm.SHA2_512));
  }

  @Test
  public void fromOid_success() throws Exception {
    assertEquals(
        AlgorithmRegistry.HashAlgorithm.SHA2_256, HashAlgorithm.fromOid(TSPAlgorithms.SHA256));
    assertEquals(
        AlgorithmRegistry.HashAlgorithm.SHA2_384, HashAlgorithm.fromOid(TSPAlgorithms.SHA384));
    assertEquals(
        AlgorithmRegistry.HashAlgorithm.SHA2_512, HashAlgorithm.fromOid(TSPAlgorithms.SHA512));
  }

  @Test
  public void fromOid_unsupported() {
    ASN1ObjectIdentifier unsupportedOid = new ASN1ObjectIdentifier("1.2.840.113549.2.5"); // MD5 OID
    UnsupportedAlgorithmException exception =
        assertThrows(
            UnsupportedAlgorithmException.class, () -> HashAlgorithm.fromOid(unsupportedOid));
    assertEquals(
        "Unsupported timestamp hashing algorithm oid: 1.2.840.113549.2.5", exception.getMessage());
  }
}
