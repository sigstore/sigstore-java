/*
 * Copyright 2024 The Sigstore Authors.
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
package dev.sigstore.tuf.encryption;

import dev.sigstore.tuf.model.Key;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class Verifiers {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @FunctionalInterface
  public interface Supplier {
    Verifier newVerifier(Key key) throws IOException, InvalidKeyException;
  }

  public static Verifier newVerifier(Key key) throws IOException, InvalidKeyException {

    PublicKey publicKey = parsePublicKey(key);
    if (key.getKeyType().equals("rsa") && key.getScheme().equals("rsassa-pss-sha256")) {
      return new RsaPssVerifier(publicKey);
    }
    if (isEcdsaKey(key) && key.getScheme().equals("ecdsa-sha2-nistp256")) {
      return new EcdsaVerifier(publicKey);
    }
    if (key.getKeyType().equals("ed25519") && key.getScheme().equals("ed25519")) {
      return new Ed25519Verifier(publicKey);
    }
    throw new InvalidKeyException(
        "Unsupported tuf key type and scheme combination: "
            + key.getKeyType()
            + "/"
            + key.getScheme());
  }

  private static PublicKey parsePublicKey(Key key) throws IOException, InvalidKeyException {
    var keyType = key.getKeyType();
    if (keyType.equals("rsa") || isEcdsaKey(key)) {
      try (PEMParser pemParser = new PEMParser(new StringReader(key.getKeyVal().get("public")))) {
        var keyObj = pemParser.readObject(); // throws DecoderException
        if (keyObj == null) {
          throw new InvalidKeyException(
              "tuf " + key.getKeyType() + " keys must be a single PEM encoded section");
        }
        if (keyObj instanceof SubjectPublicKeyInfo) {
          var keyInfo = PublicKeyFactory.createKey((SubjectPublicKeyInfo) keyObj);
          if ((keyType.equals("rsa") && keyInfo instanceof RSAKeyParameters)
              || (isEcdsaKey(key) && keyInfo instanceof ECKeyParameters)) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPublicKey((SubjectPublicKeyInfo) keyObj);
          }
        }
        throw new InvalidKeyException(
            "Could not parse PEM section into " + keyType + " public key");
      } catch (DecoderException e) {
        throw new InvalidKeyException("Could not parse PEM section in " + keyType + " public key");
      }
    }
    // tuf allows raw keys only for ed25519 (non PEM):
    // https://github.com/theupdateframework/specification/blob/c51875f445d8a57efca9dadfbd5dbdece06d87e6/tuf-spec.md#key-objects--file-formats-keys
    else if (keyType.equals("ed25519")) {
      byte[] keyContents;
      try {
        keyContents = Hex.decode(key.getKeyVal().get("public"));
      } catch (DecoderException e) {
        throw new InvalidKeyException("Could not parse hex encoded ed25519 public key");
      }
      var params =
          new SubjectPublicKeyInfo(
              new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), keyContents);
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      return converter.getPublicKey(params);
    } else {
      throw new InvalidKeyException("Unsupported tuf key type" + key.getKeyType());
    }
  }

  // this is a hack to handle keytypes of ecdsa-sha2-nistp256
  // context: https://github.com/awslabs/tough/issues/754
  private static boolean isEcdsaKey(Key key) {
    return key.getKeyType().equals("ecdsa-sha2-nistp256") || key.getKeyType().equals("ecdsa");
  }
}
