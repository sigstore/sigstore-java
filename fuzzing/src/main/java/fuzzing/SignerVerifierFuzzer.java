/*
 * Copyright 2023 The Sigstore Authors.
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
package fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.encryption.signers.Signer;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.encryption.signers.Verifier;
import dev.sigstore.encryption.signers.Verifiers;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class SignerVerifierFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(0, AlgorithmRegistry.SigningAlgorithm.values().length - 1);
      byte[] byteArray = data.consumeRemainingAsBytes();

      Signer signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.values()[choice]);
      Verifier verifier = Verifiers.newVerifier(signer.getPublicKey());

      byte[] signature1 = signer.sign(byteArray);
      byte[] signature2 = signer.signDigest(byteArray);

      var unused1 = verifier.verify(byteArray, signature1);
      var unused2 = verifier.verifyDigest(byteArray, signature2);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      // Known exception
    }
  }
}
