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

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class AlgorithmRegistry {

  // order to differentiate between the various ec curves
  private static final Map<BigInteger, SigningAlgorithm> ECDSA_ORDERS =
      Map.of(
          new BigInteger(
                  "115792089210356248762697446949407573529996955224135760342422259061068512044369"),
              SigningAlgorithm.PKIX_ECDSA_P256_SHA_256,
          new BigInteger(
                  "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"),
              SigningAlgorithm.PKIX_ECDSA_P384_SHA_384,
          new BigInteger(
                  "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"),
              SigningAlgorithm.PKIX_ECDSA_P521_SHA_512);

  /**
   * Determine the signing algorithm based on the public key.
   *
   * @param publicKey the public key
   * @return the signing algorithm
   * @throws UnsupportedAlgorithmException if the key algorithm or curve is not supported
   * @throws IllegalStateException if the public key cannot be converted into a known type
   */
  public static SigningAlgorithm getSigningAlgorithm(PublicKey publicKey)
      throws UnsupportedAlgorithmException {
    String algorithm = publicKey.getAlgorithm();
    if ("RSA".equals(algorithm)) {
      if (publicKey instanceof RSAPublicKey) {
        var rsaKey = (RSAPublicKey) publicKey;
        int bitLength = rsaKey.getModulus().bitLength();
        if (bitLength == 2048) {
          return SigningAlgorithm.PKIX_RSA_PKCS1V15_2048_SHA256;
        } else if (bitLength == 3072) {
          return SigningAlgorithm.PKIX_RSA_PKCS1V15_3072_SHA256;
        } else if (bitLength == 4096) {
          return SigningAlgorithm.PKIX_RSA_PKCS1V15_4096_SHA256;
        }
        throw new UnsupportedAlgorithmException("Unsupported RSA bit length: " + bitLength);
      }
      throw new IllegalStateException("RSA key must be an instance of RSAPublicKey");
    }
    if ("EC".equals(algorithm) || "ECDSA".equals(algorithm)) {
      if (publicKey instanceof ECPublicKey) {
        var ecKey = (ECPublicKey) publicKey;
        var order = ecKey.getParams().getOrder();
        var signingAlgorithm = ECDSA_ORDERS.get(order);
        if (signingAlgorithm == null) {
          throw new UnsupportedAlgorithmException("Unsupported EC key with order: " + order);
        }
        return signingAlgorithm;
      }
      throw new IllegalStateException("EC/ECDSA key must be an instance of ECPublicKey");
    }
    throw new UnsupportedAlgorithmException("Unsupported key algorithm: " + algorithm);
  }

  public enum SigningAlgorithm {
    PKIX_RSA_PKCS1V15_2048_SHA256(HashAlgorithm.SHA2_256),
    PKIX_RSA_PKCS1V15_3072_SHA256(HashAlgorithm.SHA2_256),
    PKIX_RSA_PKCS1V15_4096_SHA256(HashAlgorithm.SHA2_256),

    // ECDSA
    PKIX_ECDSA_P256_SHA_256(HashAlgorithm.SHA2_256),
    PKIX_ECDSA_P384_SHA_384(HashAlgorithm.SHA2_384),
    PKIX_ECDSA_P521_SHA_512(HashAlgorithm.SHA2_512);

    private final HashAlgorithm hashAlgorithm;

    SigningAlgorithm(HashAlgorithm hashAlgorithm) {
      this.hashAlgorithm = hashAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
      return hashAlgorithm;
    }
  }

  public enum HashAlgorithm {
    SHA2_256("SHA256", "sha256", 32),
    SHA2_384("SHA384", "sha384", 48),
    SHA2_512("SHA512", "sha512", 64);

    private final String name;
    private final String lowercase;
    private final int length;

    HashAlgorithm(String name, String lowercase, int length) {
      this.name = name;
      this.lowercase = lowercase;
      this.length = length;
    }

    public String toString() {
      return name;
    }

    public String toLowercaseString() {
      return lowercase;
    }

    public int getLength() {
      return length;
    }
  }
}
