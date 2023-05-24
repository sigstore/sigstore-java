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

import static org.bouncycastle.jce.ECPointUtil.decodePoint;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.DecoderException;

/** For internal use. Key related utility functions. */
public class Keys {

  private static final List<String> SUPPORTED_KEY_TYPES =
      List.of("ECDSA", "EC", "RSA", "Ed25519", "EdDSA");

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Takes a PEM formatted public key in bytes and constructs a {@code PublicKey} with it.
   *
   * <p>This method supports the follow public key algorithms: RSA, EdDSA, EC.
   *
   * @throws InvalidKeySpecException if the PEM does not contain just one public key.
   * @throws NoSuchAlgorithmException if the public key is using an unsupported algorithm.
   */
  public static PublicKey parsePublicKey(byte[] keyBytes)
      throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    try (PEMParser pemParser =
        new PEMParser(
            new InputStreamReader(new ByteArrayInputStream(keyBytes), StandardCharsets.UTF_8))) {
      var keyObj = pemParser.readObject(); // throws DecoderException
      if (keyObj == null) {
        throw new InvalidKeySpecException(
            "sigstore public keys must be only a single PEM encoded public key");
      }
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      if (keyObj instanceof SubjectPublicKeyInfo) {
        PublicKey pk = converter.getPublicKey((SubjectPublicKeyInfo) keyObj);
        if (!SUPPORTED_KEY_TYPES.contains(pk.getAlgorithm())) {
          throw new NoSuchAlgorithmException("Unsupported key type: " + pk.getAlgorithm());
        }
        return pk;
      }
      throw new InvalidKeySpecException("Could not parse PEM section into public key");
    } catch (DecoderException e) {
      throw new InvalidKeySpecException("Invalid key, could not parse PEM section");
    }
  }

  /**
   * Takes a PKIX DER formatted public key in bytes and constructs a {@code PublicKey} with it.
   *
   * <p>This method is known to work with keys algorithms: RSA, EdDSA, EC.
   *
   * @param contents the public key bytes
   * @param algorithm the key algorithm
   * @return a PublicKey object
   * @throws NoSuchAlgorithmException if we don't support the scheme provided
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey parsePkixPublicKey(byte[] contents, String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    X509EncodedKeySpec spec = new X509EncodedKeySpec(contents);
    KeyFactory factory = KeyFactory.getInstance(algorithm);
    return factory.generatePublic(spec);
  }

  public static PublicKey parsePkcs1RsaPublicKey(byte[] contents)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    ASN1Sequence sequence = ASN1Sequence.getInstance(contents);
    ASN1Integer modulus = ASN1Integer.getInstance(sequence.getObjectAt(0));
    ASN1Integer exponent = ASN1Integer.getInstance(sequence.getObjectAt(1));
    RSAPublicKeySpec keySpec =
        new RSAPublicKeySpec(modulus.getPositiveValue(), exponent.getPositiveValue());
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePublic(keySpec);
  }

  /**
   * Valid values for scheme are:
   *
   * <ol>
   *   <li><a href="https://ed25519.cr.yp.to/">ed25519</a>
   *   <li><a
   *       href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ecdsa-sha2-nistp256</a>
   * </ol>
   *
   * @see <a
   *     href="https://theupdateframework.github.io/specification/latest/index.html#role-role">spec</a>
   * @param contents keyBytes
   * @param scheme signing scheme
   * @return java {link PublicKey}
   * @throws NoSuchAlgorithmException if we don't support the scheme provided
   * @throws InvalidKeySpecException if the public key material is invalid
   */
  public static PublicKey constructTufPublicKey(byte[] contents, String scheme)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    if (contents == null || contents.length == 0) {
      throw new InvalidKeySpecException("key contents was empty");
    }
    switch (scheme) {
      case "ed25519":
        {
          final KeyFactory kf = KeyFactory.getInstance("Ed25519");
          X509EncodedKeySpec keySpec;
          // tuf allows raw keys only for ed25519 (non PEM):
          // https://github.com/theupdateframework/specification/blob/c51875f445d8a57efca9dadfbd5dbdece06d87e6/tuf-spec.md#key-objects--file-formats-keys
          if (contents.length == 32) {
            var params =
                new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), contents);
            try {
              keySpec = new X509EncodedKeySpec(params.getEncoded());
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          } else {
            keySpec = new X509EncodedKeySpec(contents);
          }
          return kf.generatePublic(keySpec);
        }
      case "ecdsa":
      case "ecdsa-sha2-nistp256":
        {
          // spec for P-256 curve
          ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("P-256");
          // create a KeyFactory with ECDSA (Elliptic Curve Diffie-Hellman) algorithm and use
          // BouncyCastle as the provider
          KeyFactory kf = null;
          try {
            kf = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
          } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
          }

          // code below just creates the public key from key contents using the curve parameters
          // (spec variable)
          try {
            ECNamedCurveSpec params =
                new ECNamedCurveSpec("P-256", spec.getCurve(), spec.getG(), spec.getN());
            ECPoint point = decodePoint(params.getCurve(), contents);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            return kf.generatePublic(pubKeySpec);
          } catch (IllegalArgumentException | NullPointerException ex) {
            throw new InvalidKeySpecException("ecdsa key was not parseable", ex);
          }
        }
      default:
        throw new RuntimeException(scheme + " not currently supported");
    }
  }
}
