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

/** Factory class for creation of signers. */
public class Signers {

  /** Create a new ECDSA signer with 256 bit keysize. */
  public static EcdsaSigner newEcdsaSigner() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(256);
    return new EcdsaSigner(keyGen.generateKeyPair());
  }

  /** Create a new RSA signer with 2048 bit keysize. */
  public static RsaSigner newRsaSigner() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    return new RsaSigner(keyGen.generateKeyPair());
  }
}
