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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/** For internal use. Key related utility functions. */
public class Keys {

  private static final Logger log = Logger.getLogger(Keys.class.getName());

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
    PemObject section = pemReader.readPemObject();
    if (pemReader.readPemObject() != null) {
      throw new InvalidKeySpecException(
          "ctfe public key must be only a single PEM encoded public key");
    }
    byte[] content = section.getContent();
    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(content);
    AsymmetricKeyParameter keyParameters = PublicKeyFactory.createKey(content);

    // get algorithm inspecting the created class
    String keyAlgorithm = extractKeyAlgorithm(keyParameters);
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
    return keyFactory.generatePublic(publicKeySpec);
  }

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
              "The key provided was of type: %s. We only support RSA, EdDSA, and EC ",
              keyParameters);
      log.severe(error);
      throw new NoSuchAlgorithmException(error);
    }
  }
}
