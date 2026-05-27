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
import dev.sigstore.UnsupportedAlgorithmException;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/** Autodetection for verification algorithms based on public keys used. */
public class Verifiers {
  /**
   * Returns a new verifier for the provided public key to use during verification. Hash algorithm
   * is automatically determined from the {@link AlgorithmRegistry}.
   */
  public static Verifier newVerifier(PublicKey publicKey) throws UnsupportedAlgorithmException {
    if (publicKey.getAlgorithm().equals("RSA")) {
      return new RsaVerifier(
          publicKey, AlgorithmRegistry.getSigningAlgorithm(publicKey).getHashAlgorithm());
    }
    if (publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA")) {
      return new EcdsaVerifier(
          publicKey, AlgorithmRegistry.getSigningAlgorithm(publicKey).getHashAlgorithm());
    }
    if (publicKey.getAlgorithm().equals("Ed25519")) {
      return new Ed25519Verifier(publicKey);
    }
    if (publicKey.getAlgorithm().equals("EdDSA")) {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      if (spki.getAlgorithm() != null
          && new ASN1ObjectIdentifier("1.3.101.112").equals(spki.getAlgorithm().getAlgorithm())) {
        return new Ed25519Verifier(publicKey);
      }
      throw new UnsupportedAlgorithmException(
          "Cannot verify signatures for non-Ed25519 EdDSA key types, this client only supports RSA, ECDSA, and Ed25519 verification");
    }
    throw new UnsupportedAlgorithmException(
        "Cannot verify signatures for key type '"
            + publicKey.getAlgorithm()
            + "', this client only supports RSA, ECDSA, and Ed25519 verification");
  }

  /**
   * Returns a verifier that is bound to a specific hash algorithm, useful for legacy signing using
   * algorithms combinations not available in the {@link AlgorithmRegistry}.
   */
  public static Verifier newVerifier(
      PublicKey publicKey, AlgorithmRegistry.HashAlgorithm hashAlgorithm)
      throws UnsupportedAlgorithmException {
    if (publicKey.getAlgorithm().equals("RSA")) {
      return new RsaVerifier(publicKey, hashAlgorithm);
    }
    if (publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA")) {
      return new EcdsaVerifier(publicKey, hashAlgorithm);
    }
    throw new UnsupportedAlgorithmException(
        "Cannot verify signatures for key type '"
            + publicKey.getAlgorithm()
            + "', this client only supports RSA, ECDSA verification when specifying hash algorithm");
  }
}
