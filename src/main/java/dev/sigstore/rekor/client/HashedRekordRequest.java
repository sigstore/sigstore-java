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
import dev.sigstore.rekor.*;
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
   * @param artifactDigest the sha256 digest of the artifact (not hex/base64 encoded)
   * @param publicKey the pem encoded public key or public key certificate used to verify {@code
   *     signature}. Certificates in keyless signing are typically obtained from fulcio.
   * @param signature the signature over the {@code artifactDigest} (not hex/base64 encoded)
   */
  public static HashedRekordRequest newHashedRekordRequest(
      byte[] artifactDigest, byte[] publicKey, byte[] signature) {

    return new HashedRekordRequest(
        new HashedRekord()
            .withData(
                new Data()
                    .withHash(
                        new Hash()
                            .withValue(new String(Hex.encode(artifactDigest)))
                            .withAlgorithm(Hash.Algorithm.SHA_256)))
            .withSignature(
                new Signature()
                    .withContent(Base64.getEncoder().encodeToString(signature))
                    .withPublicKey(
                        new PublicKey()
                            .withContent(Base64.getEncoder().encodeToString(publicKey)))));
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
