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

import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.signers.Verifiers;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.LinkedHashMap;

/** Verifier for rekor entries. */
public class RekorVerifier {
  private final PublicKey rekorPublicKey;
  private final String verifierAlgorithm;

  public static RekorVerifier newRekorVerifier(byte[] rekorPublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    var publicKey = Keys.parsePublicKey(rekorPublicKey);
    var verifierAlgorithm = Verifiers.signatureAlgorithm(publicKey);

    return new RekorVerifier(publicKey, verifierAlgorithm);
  }

  private RekorVerifier(PublicKey rekorPublicKey, String verifierAlgorithm) {
    this.rekorPublicKey = rekorPublicKey;
    this.verifierAlgorithm = verifierAlgorithm;
  }

  /**
   * Verify that a Rekor Entry is signed with the rekor public key loaded into this verifier
   *
   * @param entry the entry to verify
   * @throws RekorVerificationException if the entry cannot be verified
   */
  public void verifyEntry(RekorEntry entry)
      throws RekorVerificationException, NoSuchAlgorithmException, InvalidKeyException,
          SignatureException {
    if (entry.getVerification() == null) {
      throw new RekorVerificationException("No verification information in entry.");
    }

    if (entry.getVerification().getSignedEntryTimestamp() == null) {
      throw new RekorVerificationException("No signed entry timestamp found in entry.");
    }

    // use a LinkedHashMap to preserve order, json must be canonical
    // (https://datatracker.ietf.org/doc/html/rfc8785)
    var signableContent = new LinkedHashMap<String, Object>();
    signableContent.put("body", entry.getBody());
    signableContent.put("integratedTime", entry.getIntegratedTime());
    signableContent.put("logID", entry.getLogID());
    signableContent.put("logIndex", entry.getLogIndex());

    // TODO: I think we can verify the logID (sha256 of log public key) here too
    // to provide the user with some useful information
    // (https://github.com/sigstore/sigstore-java/issues/34)

    var signableJson = GSON.get().toJson(signableContent);

    var verifier = Signature.getInstance(verifierAlgorithm);
    verifier.initVerify(rekorPublicKey);
    verifier.update(signableJson.getBytes(StandardCharsets.UTF_8));
    if (!verifier.verify(
        Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
      throw new RekorVerificationException("Entry SET was not valid");
    }
  }

  /**
   * Verify that a Rekor Entry is in the log by checking inclusion proof.
   *
   * @param entry the entry to verify
   * @throws RekorVerificationException if the entry cannot be verified
   */
  public void verifyInclusionProof(RekorEntry entry) throws RekorVerificationException {
    throw new UnsupportedOperationException("Verifying inclusion proof is not yet supported");
  }
}
