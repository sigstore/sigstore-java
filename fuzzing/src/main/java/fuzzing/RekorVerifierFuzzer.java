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
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorResponse;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.rekor.client.RekorVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class RekorVerifierFuzzer {
  private final static String URL = "https://false.url.for.RekorTypes.fuzzing.com";

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Boolean choice = data.consumeBoolean();
      byte[] byteArray = data.consumeRemainingAsBytes();
      String string = new String(byteArray, StandardCharsets.UTF_8);

      URI uri = new URI(URL);
      RekorEntry entry = RekorResponse.newRekorResponse(uri, string).getEntry();
      RekorVerifier verifier = RekorVerifier.newRekorVerifier(byteArray);

      if (choice) {
        verifier.verifyEntry(entry);
      } else {
        verifier.verifyInclusionProof(entry);
      }
    } catch (URISyntaxException
        | InvalidKeySpecException
        | NoSuchAlgorithmException
        | IOException
        | RekorVerificationException e) {
      // Known exception
    }
  }
}
