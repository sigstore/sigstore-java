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
package dev.sigstore.bundle;

import com.google.protobuf.InvalidProtocolBufferException;
import dev.sigstore.KeylessSignature;
import dev.sigstore.proto.bundle.v1.Bundle;
import java.io.Reader;
import java.util.List;

/**
 * Generates Sigstore Bundle.
 *
 * @see <a href="https://github.com/sigstore/protobuf-specs">Sigstore Bundle Protobuf
 *     specifications</a>
 */
public class BundleFactory {
  /**
   * Generates Sigstore Bundle JSON from {@link KeylessSignature}.
   *
   * @param signingResult Keyless signing result.
   * @return Sigstore Bundle in JSON format
   */
  public static String createBundle(KeylessSignature signingResult) {
    Bundle bundle = BundleFactoryInternal.createBundleBuilder(signingResult).build();
    try {
      String jsonBundle = BundleFactoryInternal.JSON_PRINTER.print(bundle);
      List<String> missingFields = BundleVerifierInternal.findMissingFields(bundle);
      if (!missingFields.isEmpty()) {
        throw new IllegalStateException(
            "Some of the fields were not initialized: "
                + String.join(", ", missingFields)
                + "; bundle JSON: "
                + jsonBundle);
      }
      return jsonBundle;
    } catch (InvalidProtocolBufferException e) {
      throw new IllegalArgumentException(
          "Can't serialize signing result to Sigstore Bundle JSON", e);
    }
  }

  /**
   * Read a bundle json and convert it back into a keyless signing result for use within this
   * library
   *
   * @param jsonReader a reader to a valid bundle json file
   * @return the converted signing result object
   * @throws BundleParseException if all or parts of the bundle were not convertible to library
   *     types
   */
  public static KeylessSignature readBundle(Reader jsonReader) throws BundleParseException {
    return BundleFactoryInternal.readBundle(jsonReader);
  }
}
