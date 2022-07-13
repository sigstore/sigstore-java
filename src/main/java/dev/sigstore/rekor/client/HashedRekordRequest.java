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

import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.rekor.*;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Hex;

public class HashedRekordRequest {

  private final Hashedrekord hashedrekord;

  private HashedRekordRequest(Hashedrekord hashedrekord) {
    this.hashedrekord = hashedrekord;
  }

  /**
   * Create a new HashedRekorRequest.
   *
   * @param artifactDigest the sha256 digest of the artifact (not hex/base64 encoded)
   * @param leafCert the leaf certificate used to verify {@code signature}, usually obtained from
   *     fulcio
   * @param signature the signature over the {@code artifactDigest} (not hex/base64 encoded)
   */
  public static HashedRekordRequest newHashedRekordRequest(
      byte[] artifactDigest, Certificate leafCert, byte[] signature) throws IOException {

    var certPem = Certificates.toPemBytes(leafCert);
    var hashedrekord =
        new Hashedrekord()
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
                        new PublicKey().withContent(Base64.getEncoder().encodeToString(certPem))));
    return new HashedRekordRequest(hashedrekord);
  }

  public String toJsonPayload() {
    var data = new HashMap<String, Object>();
    data.put("kind", "hashedrekord");
    data.put("apiVersion", "0.0.1");
    data.put("spec", hashedrekord);

    return GSON.get().toJson(data);
  }

  public Hashedrekord getHashedrekord() {
    return hashedrekord;
  }
}
