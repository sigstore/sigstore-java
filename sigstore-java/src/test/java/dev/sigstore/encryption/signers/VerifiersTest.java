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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

/** VerifiersTest for failure cases, passing cases are handled in {@link SignerTest}. */
public class VerifiersTest {
  private static final byte[] CONTENT = "abcdef".getBytes(StandardCharsets.UTF_8);

  @Test
  public void verify_ed25519_withBcProvider() throws Exception {
    var kp = genKeyPairWithBcProvider("ed25519");
    var signature = genSignature(kp, "ed25519");
    var verifier = Verifiers.newVerifier(kp.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  @Test
  public void verify_ed25519_withoutBcProvider() throws Exception {
    var kp = genKeyPair("ed25519");
    var signature = genSignature(kp, "ed25519");
    var verifier = Verifiers.newVerifier(kp.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  @Test
  public void verify_ed448_withBcProvider() throws Exception {
    var kp = genKeyPairWithBcProvider("ed448");
    var signature = genSignature(kp, "ed448");
    var exception =
        Assertions.assertThrows(
            NoSuchAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
    Assertions.assertEquals(
        "Cannot verify signatures for key type 'Ed448', this client only supports RSA, ECDSA, and Ed25519 verification",
        exception.getMessage());
  }

  @Test
  @EnabledForJreRange(min = JRE.JAVA_15)
  public void verify_ed448_withoutBcProvider() throws Exception {
    var kp = genKeyPair("ed448");
    var signature = genSignature(kp, "ed448");
    var exception =
        Assertions.assertThrows(
            NoSuchAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
    Assertions.assertEquals(
        "Cannot verify signatures for non-Ed25519 EdDSA key types, this client only supports RSA, ECDSA, and Ed25519 verification",
        exception.getMessage());
  }

  @Test
  public void verify_unknown() throws Exception {
    var kp = KeyPairGenerator.getInstance("DSA").generateKeyPair();
    var exception =
        Assertions.assertThrows(
            NoSuchAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
    Assertions.assertEquals(
        exception.getMessage(),
        "Cannot verify signatures for key type 'DSA', this client only supports RSA, ECDSA, and Ed25519 verification");
  }

  private KeyPair genKeyPair(String algorithm) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm);
    return kpGen.generateKeyPair();
  }

  private KeyPair genKeyPairWithBcProvider(String algorithm) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");
    return kpGen.generateKeyPair();
  }

  private byte[] genSignature(KeyPair keyPair, String algorithm) throws Exception {
    Signature signature = Signature.getInstance(algorithm);
    signature.initSign(keyPair.getPrivate());
    signature.update(CONTENT);
    return signature.sign();
  }
}
