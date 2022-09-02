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

/** A verifier helper that wraps common verification operations for use within this library. */
public interface Verifier {

  /** Return the public key associated with this verifier. */
  PublicKey getPublicKey();

  /**
   * Verify an artifact. Implementations will hash the artifact with sha256 before verifying.
   *
   * @param artifact the artifact that was signed
   * @param signature the signature associated with the artifact
   * @return true if the signature is valid, false otherwise
   */
  boolean verify(byte[] artifact, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

  /**
   * Verify an artifact using the artifact's sha256 digest. Implementations do not further hash the
   * input.
   *
   * @param artifactDigest the sha256 digest of the artifact that was signed
   * @param signature the signature associated with the artifact
   * @return true if the signature is valid, false otherwise
   */
  boolean verifyDigest(byte[] artifactDigest, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
