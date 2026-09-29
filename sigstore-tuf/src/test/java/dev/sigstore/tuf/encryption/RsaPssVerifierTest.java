/*
 * Copyright 2024 The Sigstore Authors.
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
package dev.sigstore.tuf.encryption;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class RsaPssVerifierTest {

  private static final byte[] CONTENT = "abcdef".getBytes(StandardCharsets.UTF_8);

  @Test
  public void testVerify_RsaPss() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    var keyPair = genKeyPair();
    var signature = genSignature(keyPair);
    var verifier = new RsaPssVerifier(keyPair.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  private KeyPair genKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    return keyGen.genKeyPair();
  }

  private byte[] genSignature(KeyPair keyPair) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSAandMGF1");
    signature.initSign(keyPair.getPrivate());
    signature.update(CONTENT);
    return signature.sign();
  }
}
