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

import java.io.IOException;
import java.io.InputStream;
import java.security.*;

/** RSA signer, use {@link Signers#newRsaSigner()} to instantiate}. */
public class RsaSigner implements Signer {

  private final KeyPair keyPair;

  RsaSigner(KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  @Override
  public PublicKey getPublicKey() {
    return keyPair.getPublic();
  }

  @Override
  public byte[] sign(byte[] artifact)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(keyPair.getPrivate());
    signature.update(artifact);
    return signature.sign();
  }

  @Override
  public byte[] sign(InputStream artifact)
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(keyPair.getPrivate());
    int b;
    while ((b = artifact.read()) != -1) {
      signature.update((byte) b);
    }
    return signature.sign();
  }
}
