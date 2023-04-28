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
import dev.sigstore.bundle.BundleFactory;
import dev.sigstore.bundle.BundleParseException;
import dev.sigstore.bundle.BundleVerifier;
import java.io.StringReader;

public class BundleFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Boolean choice = data.consumeBoolean();
      String string = data.consumeRemainingAsString();

      if (choice) {
        BundleFactory.createBundle(BundleFactory.readBundle(new StringReader(string)));
      } else {
        BundleVerifier.findMissingFields(string);
      }
    } catch (BundleParseException e) {
    } catch (IllegalArgumentException e) {
    }
  }
}
