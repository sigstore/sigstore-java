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

/** ECDSA signer, use {@link Signers#newEcdsaSigner()} to instantiate}. */
public class EcdsaSigner implements Signer {

  private final KeyPair keyPair;

  EcdsaSigner(KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  @Override
  public PublicKey getPublicKey() {
    return keyPair.getPublic();
  }

  @Override
  public byte[] sign(byte[] artifact)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(keyPair.getPrivate());
    signature.update(artifact);
    return signature.sign();
  }

  @Override
  public byte[] signDigest(byte[] artifactDigest)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    if (artifactDigest.length > 64) {
      throw new SignatureExeption("Artifact digest cannot be longer than 64 bytes for this mode");
    }
    Signature signature = Signature.getInstance("NONEwithECDSA");
    signature.initSign(keyPair.getPrivate());
    signature.update(artifactDigest);
    return signature.sign();
  }
}
