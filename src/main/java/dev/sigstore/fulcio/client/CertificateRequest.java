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
package dev.sigstore.fulcio.client;

import static dev.sigstore.json.GsonSupplier.GSON;

import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import org.immutables.value.Value;

@Value.Immutable
public abstract class CertificateRequest {
  public static final List<String> SUPPORTED_ALGORITHMS = Collections.singletonList("EC");

  public abstract PublicKey getPublicKey();

  public abstract byte[] getProofOfPossession();

  public abstract String getIdToken();

  /**
   * Create a certificate request
   *
   * @param publicKey An ECDSA public key
   * @param idToken An oidc token obtained from an oauth provider
   * @param proofOfPossession The subject or email address from {@code idToken}, signed by the
   *     private key counterpart of {@code publicKey} in asn1 notation
   * @throws UnsupportedAlgorithmException if key type is not in {@link
   *     CertificateRequest#SUPPORTED_ALGORITHMS}
   */
  public static CertificateRequest newCertificateRequest(
      PublicKey publicKey, String idToken, byte[] proofOfPossession)
      throws UnsupportedAlgorithmException {
    if (!SUPPORTED_ALGORITHMS.contains(publicKey.getAlgorithm())) {
      throw new UnsupportedAlgorithmException(SUPPORTED_ALGORITHMS, publicKey.getAlgorithm());
    }
    return ImmutableCertificateRequest.builder()
        .publicKey(publicKey)
        .idToken(idToken)
        .proofOfPossession(proofOfPossession)
        .build();
  }

  public String toJsonPayload() {
    HashMap<String, Object> key = new HashMap<>();
    key.put("content", getPublicKey().getEncoded());
    key.put("algorithm", getPublicKey().getAlgorithm());

    HashMap<String, Object> data = new HashMap<>();
    data.put("publicKey", key);
    data.put("signedEmailAddress", getProofOfPossession());

    return GSON.get().toJson(data);
  }
}
