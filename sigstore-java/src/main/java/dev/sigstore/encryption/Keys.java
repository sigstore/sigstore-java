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

import static org.bouncycastle.jce.ECPointUtil.*;

import com.google.common.annotations.VisibleForTesting;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Locale;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/** For internal use. Key related utility functions. */
public class Keys {

  private static final Logger log = Logger.getLogger(Keys.class.getName());

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
    PemReader pemReader =
        new PemReader(
            new InputStreamReader(new ByteArrayInputStream(keyBytes), StandardCharsets.UTF_8));
    PemObject section = null;
    try {
      section = pemReader.readPemObject();
      if (pemReader.readPemObject() != null) {
        throw new InvalidKeySpecException(
            "sigstore public keys must be only a single PEM encoded public key");
      }
    } catch (DecoderException e) {
      throw new InvalidKeySpecException("Invalid key, could not parse PEM section");
    }
    // special handling for PKCS1 (rsa) public key
    if (section == null) {
      throw new InvalidKeySpecException("Invalid key");
    }
    if (section.getType().equals("RSA PUBLIC KEY")) {
      ASN1Sequence sequence = ASN1Sequence.getInstance(section.getContent());
      ASN1Integer modulus = ASN1Integer.getInstance(sequence.getObjectAt(0));
      ASN1Integer exponent = ASN1Integer.getInstance(sequence.getObjectAt(1));
      RSAPublicKeySpec keySpec =
          new RSAPublicKeySpec(modulus.getPositiveValue(), exponent.getPositiveValue());
      KeyFactory factory = KeyFactory.getInstance("RSA");
      return factory.generatePublic(keySpec);
    }

    // otherwise, we are dealing with PKIX X509 encoded keys
    byte[] content = section.getContent();
    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(content);
    AsymmetricKeyParameter keyParameters = null;

    // Ensure PEM content can be parsed correctly
    try {
      keyParameters = PublicKeyFactory.createKey(content);
    } catch (IllegalStateException e) {
      throw new InvalidKeySpecException("Invlid key, could not parse PEM content");
    }
    if (keyParameters == null) {
      throw new InvalidKeySpecException("Invlid key, could not parse PEM content");
    }

    // get algorithm inspecting the created class
    String keyAlgorithm = extractKeyAlgorithm(keyParameters);
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
    return keyFactory.generatePublic(publicKeySpec);
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
    PublicKey publicKey = null;
    switch (scheme) {
      case "rsassa-pss-sha256":
        throw new RuntimeException("rsassa-pss-sha256 not currently supported");
      case "ed25519":
        {
          final KeyFactory kf = KeyFactory.getInstance("Ed25519");
          final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(contents);
          publicKey = kf.generatePublic(keySpec);
          break;
        }
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
          ECNamedCurveSpec params =
              new ECNamedCurveSpec("P-256", spec.getCurve(), spec.getG(), spec.getN());
          ECPoint point = decodePoint(params.getCurve(), contents);
          ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
          publicKey = kf.generatePublic(pubKeySpec);
          break;
        }
    }
    return publicKey;
  }

  // https://stackoverflow.com/questions/42911637/get-publickey-from-key-bytes-not-knowing-the-key-algorithm
  private static String extractKeyAlgorithm(AsymmetricKeyParameter keyParameters)
      throws NoSuchAlgorithmException {
    if (keyParameters instanceof RSAKeyParameters) {
      return "RSA";
    } else if (keyParameters instanceof Ed25519PublicKeyParameters) {
      return "EdDSA";
    } else if (keyParameters instanceof ECKeyParameters) {
      return "EC";
    } else {
      String error =
          String.format(
              Locale.ROOT,
              "The key provided was of type: %s. We only support RSA, EdDSA, and EC ",
              keyParameters);
      log.warning(error);
      throw new NoSuchAlgorithmException(error);
    }
  }

  @VisibleForTesting
  protected static int getJavaVersion() {
    return getJavaVersion(System.getProperty("java.version"));
  }

  @VisibleForTesting
  protected static int getJavaVersion(String version) {
    return Integer.parseInt(version.substring(0, version.indexOf(".")));
  }
}
