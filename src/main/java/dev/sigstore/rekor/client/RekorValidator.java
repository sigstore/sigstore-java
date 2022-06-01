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

import dev.sigstore.encryption.Keys;
import dev.sigstore.json.GsonSupplier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.LinkedHashMap;

/** Validator for rekor entries. */
public class RekorValidator {
  private final PublicKey rekorPublicKey;

  public static RekorValidator newRekorValidator(byte[] rekorPublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    // TODO: accept any keytime and appropriately initialize the signer below (currently only EC
    // compatible: https://github.com/sigstore/sigstore-java/issues/32)
    PublicKey publicKey = Keys.parsePublicKey(rekorPublicKey);
    return new RekorValidator(publicKey);
  }

  private RekorValidator(PublicKey rekorPublicKey) {
    this.rekorPublicKey = rekorPublicKey;
  }

  /**
   * Validate that a Rekor Entry is signed with the rekor public key loaded into this validator
   *
   * @param entry the entry to validate
   * @throws RekorValidationException if the entry cannot be validated
   */
  public void validateEntry(RekorEntry entry)
      throws RekorValidationException, NoSuchAlgorithmException, InvalidKeyException,
          SignatureException {
    if (entry.getVerification() == null) {
      throw new RekorValidationException("No verification information in entry.");
    }

    if (entry.getVerification().getSignedEntryTimestamp() == null) {
      throw new RekorValidationException("No signed entry timestamp found in entry.");
    }

    // use a LinkedHashMap to preserve order, json must be canonical
    // (https://datatracker.ietf.org/doc/html/rfc8785)
    var signableContent = new LinkedHashMap<String, Object>();
    signableContent.put("body", entry.getBody());
    signableContent.put("integratedTime", entry.getIntegratedTime());
    signableContent.put("logID", entry.getLogID());
    signableContent.put("logIndex", entry.getLogIndex());

    var signableJson = new GsonSupplier().get().toJson(signableContent);

    // TODO: Validate more than just "ec" signed rekor entries
    // (https://github.com/sigstore/sigstore-java/issues/32)
    var verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(rekorPublicKey);
    verifier.update(signableJson.getBytes(StandardCharsets.UTF_8));
    if (!verifier.verify(
        Base64.getDecoder().decode(entry.getVerification().getSignedEntryTimestamp()))) {
      throw new RekorValidationException("Entry SET was not valid");
    }
  }

  /**
   * Validate that a Rekor Entry is in the log by checking inclusion proof.
   *
   * @param entry the entry to validate
   * @throws RekorValidationException if the entry cannot be validated
   */
  public void validateInclusionProof(RekorEntry entry) {
    throw new UnsupportedOperationException("Validating inclusion proof is not yet supported");
  }
}
