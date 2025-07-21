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

import dev.sigstore.AlgorithmRegistry;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/** Factory class for creation of signers. */
public class Signers {

  /** Create a new signer from the algorithm registry. */
  public static Signer from(AlgorithmRegistry.SigningAlgorithm algorithm) {
    switch (algorithm) {
      case PKIX_RSA_PKCS1V15_2048_SHA256:
        return newRsaSigner(2048, AlgorithmRegistry.HashAlgorithm.SHA2_256);
      case PKIX_RSA_PKCS1V15_3072_SHA256:
        return newRsaSigner(3072, AlgorithmRegistry.HashAlgorithm.SHA2_256);
      case PKIX_RSA_PKCS1V15_4096_SHA256:
        return newRsaSigner(4096, AlgorithmRegistry.HashAlgorithm.SHA2_256);
      case PKIX_ECDSA_P256_SHA_256:
        return newEcdsaSigner("secp256r1", AlgorithmRegistry.HashAlgorithm.SHA2_256);
    }
    throw new IllegalStateException("Unknown algorithm: " + algorithm);
  }

  static EcdsaSigner newEcdsaSigner(String spec, AlgorithmRegistry.HashAlgorithm hashAlgorithm) {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(new ECGenParameterSpec(spec));
      return new EcdsaSigner(keyGen.generateKeyPair(), hashAlgorithm);
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException nse) {
      throw new RuntimeException("No EC algorithm found in Runtime", nse);
    }
  }

  /** Create a new RSA signer with 2048 bit keysize. */
  static RsaSigner newRsaSigner(int keysize, AlgorithmRegistry.HashAlgorithm hashAlgorithm) {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(keysize);
      return new RsaSigner(keyGen.generateKeyPair(), hashAlgorithm);
    } catch (NoSuchAlgorithmException nse) {
      throw new RuntimeException("No RSA algorithm found in Runtime", nse);
    }
  }
}
