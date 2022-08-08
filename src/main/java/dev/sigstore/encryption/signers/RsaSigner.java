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
import org.bouncycastle.util.encoders.Hex;

/** RSA signer, use {@link Signers#newRsaSigner()} to instantiate}. */
public class RsaSigner implements Signer {

  // digest padding: https://www.rfc-editor.org/rfc/rfc3447#section-9.2
  static final byte[] PKCS1_SHA256_PADDING = Hex.decode("3031300d060960864801650304020105000420");

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
  public byte[] signDigest(byte[] artifactDigest)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance("NONEwithRSA");
    signature.initSign(keyPair.getPrivate());
    signature.update(PKCS1_SHA256_PADDING);
    signature.update(artifactDigest);
    return signature.sign();
  }
}
