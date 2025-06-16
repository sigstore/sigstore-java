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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** VerifiersTest for failure cases, passing cases are handled in {@link SignerTest}. */
public class VerifiersTest {

  @Test
  public void signatureAlgorithm_unknown() throws Exception {
    var kp = KeyPairGenerator.getInstance("DSA").generateKeyPair();
    var exception =
        Assertions.assertThrows(
            NoSuchAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
    Assertions.assertEquals(
        exception.getMessage(),
        "Cannot verify signatures for key type 'DSA', this client only supports RSA, ECDSA, and Ed25519 verification");
  }

  @Test
  public void signatureAlgorithmForDigests_unknown() throws Exception {
    var kp = KeyPairGenerator.getInstance("DSA").generateKeyPair();
    var exception =
        Assertions.assertThrows(
            NoSuchAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
    Assertions.assertEquals(
        exception.getMessage(),
        "Cannot verify signatures for key type 'DSA', this client only supports RSA, ECDSA, and Ed25519 verification");
  }
}
