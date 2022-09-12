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

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

/** Autodetection for verification algorithms based on public keys used. */
public class Verifiers {

  /** Returns a new verifier for the provided public key to use during verificaiton. */
  public static Verifier newVerifier(PublicKey publicKey) throws NoSuchAlgorithmException {
    if (publicKey.getAlgorithm().equals("RSA")) {
      return new RsaVerifier(publicKey);
    }
    if (publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA")) {
      return new EcdsaVerifier(publicKey);
    }
    throw new NoSuchAlgorithmException(
        "Cannot verify signatures for key type '"
            + publicKey.getAlgorithm()
            + "', this client only supports RSA and ECDSA verification");
  }
}
