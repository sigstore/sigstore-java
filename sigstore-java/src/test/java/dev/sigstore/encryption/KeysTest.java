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
package dev.sigstore.encryption;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.common.io.Resources;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeysTest {

  static final String RSA_PUB_PATH = "dev/sigstore/samples/keys/test-rsa.pub";
  static final String RSA_PUB_PKCS1_PATH = "dev/sigstore/samples/keys/test-rsa-pkcs1.pub";
  static final String EC_PUB_PATH = "dev/sigstore/samples/keys/test-ec.pub";
  static final String ED25519_PUB_PATH = "dev/sigstore/samples/keys/test-ed25519.pub";
  static final String DSA_PUB_PATH = "dev/sigstore/samples/keys/test-dsa.pub";

  @Test
  void parsePublicKey_rsa() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey result =
        Keys.parsePublicKey(Resources.toByteArray(Resources.getResource(RSA_PUB_PATH)));
    assertEquals(result.getAlgorithm(), "RSA");
  }

  @Test
  void parsePublicKey_rsaPkcs1()
      throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey result =
        Keys.parsePublicKey(Resources.toByteArray(Resources.getResource(RSA_PUB_PKCS1_PATH)));
    assertEquals(result.getAlgorithm(), "RSA");
  }

  @Test
  void parsePublicKey_ec() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey result =
        Keys.parsePublicKey(Resources.toByteArray(Resources.getResource(EC_PUB_PATH)));
    assertEquals(result.getAlgorithm(), "EC");
  }

  @Test
  void parsePublicKey_ed25519_withBouncyCastle()
      throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey result =
        Keys.parsePublicKey(Resources.toByteArray(Resources.getResource(ED25519_PUB_PATH)));
    // BouncyCastle names the algorithm differently than the JDK
    assertEquals(result.getAlgorithm(), "Ed25519");
  }

  @Test
  void parsePublicKey_dsaShouldFail() {
    Assertions.assertThrows(
        NoSuchAlgorithmException.class,
        () -> Keys.parsePublicKey(Resources.toByteArray(Resources.getResource(DSA_PUB_PATH))));
  }

  @Test
  void testGetJavaVersion() {
    assertEquals(1, Keys.getJavaVersion("1.6.0_23"));
    assertEquals(1, Keys.getJavaVersion("1.7.0"));
    assertEquals(1, Keys.getJavaVersion("1.6.0_23"));
    assertEquals(9, Keys.getJavaVersion("9.0.1"));
    assertEquals(11, Keys.getJavaVersion("11.0.4"));
    assertEquals(12, Keys.getJavaVersion("12.0.1"));
    assertEquals(15, Keys.getJavaVersion("15.0.1"));
  }
}
