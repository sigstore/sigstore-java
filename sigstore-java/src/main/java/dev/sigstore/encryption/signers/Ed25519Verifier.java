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
package dev.sigstore.encryption.signers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/** ECDSA verifier, instantiated by {@link Verifiers#newVerifier(PublicKey)}. */
class Ed25519Verifier implements Verifier {

  private final PublicKey publicKey;

  Ed25519Verifier(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /** EdDSA verifiers hash implicitly for ed25519 keys. */
  @Override
  public boolean verify(byte[] artifact, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    var verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(publicKey);
    verifier.update(artifact);
    return verifier.verify(signature);
  }

  @Override
  public boolean verifyDigest(byte[] digest, byte[] signature) {
    throw new UnsupportedOperationException(
        "Ed25519 verification requires an artifact, not a digest.");
  }
}
