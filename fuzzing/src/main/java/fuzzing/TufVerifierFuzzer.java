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
import dev.sigstore.tuf.encryption.Verifiers;
import dev.sigstore.tuf.model.ImmutableKey;
import dev.sigstore.tuf.model.Key;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Map;

public class TufVerifierFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      String keyType = data.consumeString(10);
      String scheme = data.consumeString(20);
      String keyData = data.consumeRemainingAsString();

      Key key =
          ImmutableKey.builder()
              .keyType(keyType)
              .keyVal(Map.of("public", keyData))
              .scheme(scheme)
              .build();

      Verifiers.newVerifier(key);
    } catch (IOException | InvalidKeyException e) {
      // known exceptions
    }
  }
}
