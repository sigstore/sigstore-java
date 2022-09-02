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
package dev.sigstore.encryption.signers;

import java.security.*;

/** A signing helper that wraps common signing operations for use within this library. */
public interface Signer {

  /** Return the public key associated with this signer. */
  PublicKey getPublicKey();

  /**
   * Sign an artifact. Implementations will hash the artifact with sha256 before signing.
   *
   * @param artifact the bytes to be signed
   */
  byte[] sign(byte[] artifact)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

  /**
   * Sign an artifact digest. Implementations will not further hash the inputs.
   *
   * @param artifactDigest the sha256 digest of the artifact to be signed
   */
  byte[] signDigest(byte[] artifactDigest)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
