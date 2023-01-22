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
package dev.sigstore.bundle;

import dev.sigstore.proto.bundle.v1.Bundle;
import java.util.List;

/**
 * Verifies if Sigstore Bundle is valid.
 *
 * @see <a href="https://github.com/sigstore/protobuf-specs">Sigstore Bundle Protobuf
 *     specifications</a>
 */
public class BundleVerifier {
  /**
   * Verify if all required fields are initialized in the input protobuf message.
   *
   * @param bundleJson message to verify
   * @return list of all the missing fields
   */
  public static List<String> findMissingFields(String bundleJson) {
    Bundle.Builder bundle = BundleVerifierInternal.parseSigstoreBundle(bundleJson);
    return BundleVerifierInternal.findMissingFields(bundle);
  }
}
