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
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import dev.sigstore.encryption.Keys;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class KeysParsingFuzzer {

  @FunctionalInterface
  interface Parser {
    @CanIgnoreReturnValue
    PublicKey parse(byte[] contents) throws InvalidKeySpecException;
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Parser parser =
          data.pickValue(
              new Parser[] {
                Keys::parseRsaPkcs1, Keys::parseRsa, Keys::parseEcdsa, Keys::parseEd25519,
              });
      byte[] keyContents = data.consumeRemainingAsBytes();

      parser.parse(keyContents);

    } catch (InvalidKeySpecException e) {
      // known exceptions
    }
  }
}
