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

import static dev.sigstore.encryption.signers.Signers.newEcdsaSigner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class EcdsaSignerTest {

  private static final byte[] CONTENT = "abcdef".getBytes(StandardCharsets.UTF_8);

  @Test
  public void testSign_inputStream()
      throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
    var signer = newEcdsaSigner();

    var sig = signer.sign(new ByteArrayInputStream(CONTENT));
    Assertions.assertTrue(verify(signer, sig));
  }

  @Test
  public void testSign_bytes()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    var signer = newEcdsaSigner();
    String content = "abc";

    var sig = signer.sign(CONTENT);
    Assertions.assertTrue(verify(signer, sig));
  }

  private boolean verify(Signer signer, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    var verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(signer.getPublicKey());
    verifier.update(CONTENT);
    return verifier.verify(signature);
  }
}
