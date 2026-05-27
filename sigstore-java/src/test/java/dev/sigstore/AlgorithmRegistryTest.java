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
package dev.sigstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

public class AlgorithmRegistryTest {

  @Test
  public void testGetHashAlgorithm_Unsupported() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("DSA");
    keyPairGen.initialize(2048);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertThrows(
        UnsupportedAlgorithmException.class,
        () -> AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_RSA_2048() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_2048_SHA256,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_RSA_3072() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(3072);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_3072_SHA256,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_RSA_4096() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(4096);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_4096_SHA256,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_EC_P256() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("EC");
    keyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_EC_P384() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("EC");
    keyPairGen.initialize(new ECGenParameterSpec("secp384r1"));
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P384_SHA_384,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_EC_P521() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("EC");
    keyPairGen.initialize(new ECGenParameterSpec("secp521r1"));
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P521_SHA_512,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_RSA_UnsupportedLength() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(1024);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertThrows(
        UnsupportedAlgorithmException.class,
        () -> AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_RSA_NotRsaPublicKey() {
    PublicKey mockRsaKey =
        new PublicKey() {
          @Override
          public String getAlgorithm() {
            return "RSA";
          }

          @Override
          public String getFormat() {
            return null;
          }

          @Override
          public byte[] getEncoded() {
            return null;
          }
        };
    assertThrows(
        IllegalStateException.class, () -> AlgorithmRegistry.getSigningAlgorithm(mockRsaKey));
  }

  @Test
  public void testGetHashAlgorithm_EC_UnsupportedCurve() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    var keyPairGen = KeyPairGenerator.getInstance("EC", "BC");
    keyPairGen.initialize(new ECGenParameterSpec("secp256k1"));
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertThrows(
        UnsupportedAlgorithmException.class,
        () -> AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetHashAlgorithm_EC_NotEcPublicKey() {
    PublicKey mockEcKey =
        new PublicKey() {
          @Override
          public String getAlgorithm() {
            return "EC";
          }

          @Override
          public String getFormat() {
            return null;
          }

          @Override
          public byte[] getEncoded() {
            return null;
          }
        };
    assertThrows(
        IllegalStateException.class, () -> AlgorithmRegistry.getSigningAlgorithm(mockEcKey));
  }
}
