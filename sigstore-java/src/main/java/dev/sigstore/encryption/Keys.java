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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** For internal use. Key related utility functions. */
public class Keys {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Takes a PKIX DER formatted ECDSA public key in bytes and constructs a {@code PublicKey} with
   * it.
   *
   * @param contents the public key bytes
   * @return a PublicKey object
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey parseEcdsa(byte[] contents) throws InvalidKeySpecException {
    return parse(contents, "ECDSA");
  }

  /**
   * Takes a PKIX DER formatted Ed25519 public key in bytes and constructs a {@code PublicKey} with
   * it.
   *
   * @param contents the public key bytes
   * @return a PublicKey object
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey parseEd25519(byte[] contents) throws InvalidKeySpecException {
    return parse(contents, "Ed25519");
  }

  /**
   * Takes a PKIX DER formatted RSA public key in bytes and constructs a {@code PublicKey} with it.
   *
   * @param contents the public key bytes
   * @return a PublicKey object
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey parseRsa(byte[] contents) throws InvalidKeySpecException {
    return parse(contents, "RSA");
  }

  /**
   * Takes a PKCS1 DER formatted RSA public key in bytes and constructs a {@code PublicKey} with it.
   *
   * @param contents the public key bytes
   * @return a PublicKey object
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey parseRsaPkcs1(byte[] contents) throws InvalidKeySpecException {
    try {
      ASN1Sequence sequence = ASN1Sequence.getInstance(contents);
      ASN1Integer modulus = ASN1Integer.getInstance(sequence.getObjectAt(0));
      ASN1Integer exponent = ASN1Integer.getInstance(sequence.getObjectAt(1));
      RSAPublicKeySpec keySpec =
          new RSAPublicKeySpec(modulus.getPositiveValue(), exponent.getPositiveValue());
      KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
      return factory.generatePublic(keySpec);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new InvalidKeySpecException("Failed to parse pkcs1 rsa key", e);
    } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static PublicKey parse(byte[] contents, String type) throws InvalidKeySpecException {
    try {
      var keySpec = new X509EncodedKeySpec(contents);
      var factory = KeyFactory.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
      return factory.generatePublic(keySpec);
    } catch (ArrayIndexOutOfBoundsException aoe) {
      throw new InvalidKeySpecException(aoe);
    } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
