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

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

public class CertificateRequest {
  public static final List<String> SUPPORTED_ALGORITHMS = Collections.singletonList("EC");
  private final PublicKey publicKey;
  private final byte[] signedEmailAddress;

  /**
   * Create a certificate request
   *
   * @param publicKey An ECDSA public key
   * @param signedEmailAddress A ECDSA SHA256 signed oidc email address in asn1 notation, this
   *     should NOT be base64 encoded
   * @throws UnsupportedAlgorithmException if key type is not in {@link
   *     CertificateRequest#SUPPORTED_ALGORITHMS}
   */
  public CertificateRequest(PublicKey publicKey, byte[] signedEmailAddress)
      throws UnsupportedAlgorithmException {
    if (!SUPPORTED_ALGORITHMS.contains(publicKey.getAlgorithm())) {
      throw new UnsupportedAlgorithmException(SUPPORTED_ALGORITHMS, publicKey.getAlgorithm());
    }
    this.publicKey = publicKey;
    this.signedEmailAddress = signedEmailAddress;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public byte[] getSignedEmailAddress() {
    return signedEmailAddress;
  }
}
