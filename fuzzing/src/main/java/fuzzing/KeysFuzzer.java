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
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class KeysFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      String[] schemes = {"ecdsa-sha2-nistp256"};
      String scheme = data.pickValue(schemes);
      byte[] byteArray = data.consumeRemainingAsBytes();

      Keys.parsePublicKey(byteArray);
      Keys.constructTufPublicKey(byteArray, scheme);
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      // known exceptions
    }
  }
}
