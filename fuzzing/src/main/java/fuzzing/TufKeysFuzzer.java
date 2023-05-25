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
import dev.sigstore.encryption.Keys;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class TufKeysFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      String[] schemes = {"rsassa-pss-sha256", "ed25519", "ecdsa-sha2-nistp256"};
      String scheme = data.pickValue(schemes);
      byte[] byteArray = data.consumeRemainingAsBytes();

      Keys.constructTufPublicKey(byteArray, scheme);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      // known exceptions
    } catch (RuntimeException e) {
      if (!e.toString().contains("not currently supported")) {
        throw e;
      }
    }
  }
}
