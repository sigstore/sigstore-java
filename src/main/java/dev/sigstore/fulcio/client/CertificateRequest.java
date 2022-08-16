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

import com.google.common.collect.ImmutableMap;
import dev.sigstore.fulcio.v2.PublicKeyAlgorithm;
import java.security.PublicKey;
import java.util.Map;
import org.immutables.value.Value;

@Value.Immutable
public interface CertificateRequest {
  Map<String, PublicKeyAlgorithm> SUPPORTED_ALGORITHMS =
      ImmutableMap.of("EC", PublicKeyAlgorithm.ECDSA, "RSA", PublicKeyAlgorithm.RSA_PSS);

  PublicKey getPublicKey();

  PublicKeyAlgorithm getPublicKeyAlgorithm();

  byte[] getProofOfPossession();

  String getIdToken();

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
  static CertificateRequest newCertificateRequest(
      PublicKey publicKey, String idToken, byte[] proofOfPossession)
      throws UnsupportedAlgorithmException {
    if (!SUPPORTED_ALGORITHMS.containsKey(publicKey.getAlgorithm())) {
      throw new UnsupportedAlgorithmException(
          SUPPORTED_ALGORITHMS.keySet(), publicKey.getAlgorithm());
    }
    return ImmutableCertificateRequest.builder()
        .publicKey(publicKey)
        .publicKeyAlgorithm(SUPPORTED_ALGORITHMS.get(publicKey.getAlgorithm()))
        .idToken(idToken)
        .proofOfPossession(proofOfPossession)
        .build();
  }
}
