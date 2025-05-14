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

import java.math.BigInteger;
import java.security.SecureRandom;
import org.immutables.value.Value;
import org.immutables.value.Value.Immutable;

@Immutable
public interface TimestampRequest {
  /** The hash algorithm used to hash the artifact. */
  HashAlgorithm getHashAlgorithm();

  /**
   * The hash of the artifact to be timestamped. For sigstore-java, this typically refers to the
   * hash of the signature (not the original artifact's hash) in a signing event.
   */
  byte[] getHash();

  /** A nonce to prevent replay attacks. Defaults to a 64-bit random number. */
  @Value.Default
  default BigInteger getNonce() {
    return new BigInteger(64, new SecureRandom());
  }

  /** Whether or not to include certificates in the response. Defaults to {@code false}. */
  @Value.Default
  default Boolean requestCertificates() {
    return false;
  }
}
