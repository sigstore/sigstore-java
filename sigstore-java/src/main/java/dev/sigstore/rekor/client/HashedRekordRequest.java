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
package dev.sigstore.rekor.client;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.rekor.hashedRekord.v0_0_1.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Hex;
import org.erdtman.jcs.JsonCanonicalizer;

public class HashedRekordRequest {

  private final HashedRekord hashedRekord;

  private HashedRekordRequest(HashedRekord hashedRekord) {
    this.hashedRekord = hashedRekord;
  }

  /**
   * Create a new HashedRekorRequest.
   *
   * @param artifactDigest the digest of the artifact (not hex/base64 encoded)
   * @param hashAlgorithm the hash algorithm used to compute the digest
   * @param publicKey the pem encoded public key or public key certificate used to verify {@code
   *     signature}. Certificates in keyless signing are typically obtained from fulcio.
   * @param signature the signature over the {@code artifactDigest} (not hex/base64 encoded)
   */
  public static HashedRekordRequest newHashedRekordRequest(
      byte[] artifactDigest,
      AlgorithmRegistry.HashAlgorithm hashAlgorithm,
      byte[] publicKey,
      byte[] signature) {

    Hash.Algorithm rekorAlg;
    switch (hashAlgorithm) {
      case SHA2_256:
        rekorAlg = Hash.Algorithm.SHA_256;
        break;
      case SHA2_384:
        rekorAlg = Hash.Algorithm.SHA_384;
        break;
      case SHA2_512:
        rekorAlg = Hash.Algorithm.SHA_512;
        break;
      default:
        throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
    }

    return new HashedRekordRequest(
        new HashedRekord()
            .withData(
                new Data()
                    .withHash(
                        new Hash()
                            .withValue(
                                new String(Hex.encode(artifactDigest), StandardCharsets.ISO_8859_1))
                            .withAlgorithm(rekorAlg)))
            .withSignature(
                new Signature()
                    .withContent(Base64.getEncoder().encodeToString(signature))
                    .withPublicKey(
                        new PublicKey()
                            .withContent(Base64.getEncoder().encodeToString(publicKey)))));
  }

  /**
   * Create a new HashedRekorRequest with SHA-256.
   *
   * @param artifactDigest the sha256 digest of the artifact (not hex/base64 encoded)
   * @param publicKey the pem encoded public key or public key certificate used to verify {@code
   *     signature}. Certificates in keyless signing are typically obtained from fulcio.
   * @param signature the signature over the {@code artifactDigest} (not hex/base64 encoded)
   */
  public static HashedRekordRequest newHashedRekordRequest(
      byte[] artifactDigest, byte[] publicKey, byte[] signature) {
    return newHashedRekordRequest(
        artifactDigest, AlgorithmRegistry.HashAlgorithm.SHA2_256, publicKey, signature);
  }

  /** Returned a canonicalized json payload. */
  public String toJsonPayload() {
    // TODO: use RekorEntryBody type here
    var data = new HashMap<String, Object>();
    data.put("kind", "hashedrekord");
    data.put("apiVersion", "0.0.1");
    data.put("spec", hashedRekord);

    try {
      return new JsonCanonicalizer(GSON.get().toJson(data)).getEncodedString();
    } catch (IOException ioe) {
      // we shouldn't be here
      throw new RuntimeException(
          "GSON generated invalid json when serializing HashedRekordRequest");
    }
  }

  public HashedRekord getHashedRekord() {
    return hashedRekord;
  }

  /** Computes the expected rekor uuid of an entry based on the content of the hashedRekord. */
  public String computeUUID() {
    var merkleContent =
        Bytes.concat(new byte[] {0x00}, toJsonPayload().getBytes(StandardCharsets.UTF_8));
    return Hashing.sha256().hashBytes(merkleContent).toString();
  }
}
