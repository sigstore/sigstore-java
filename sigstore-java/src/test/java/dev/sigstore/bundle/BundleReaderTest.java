/*
 * Copyright 2024 The Sigstore Authors.
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

import com.google.common.io.Resources;
import dev.sigstore.dsse.InTotoPayload;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class BundleReaderTest {
  @Test
  public void readV1Bundle() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle.v1.sigstore");
  }

  @Test
  public void readV1Bundle_noInclusion() {
    var ex =
        Assertions.assertThrows(
            BundleParseException.class,
            () -> readBundle("dev/sigstore/samples/bundles/bundle.v1.no.inclusion.sigstore"));
    Assertions.assertEquals("Could not find an inclusion proof", ex.getMessage());
  }

  @Test
  public void readV2Bundle() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle.v2.sigstore");
  }

  @Test
  public void readV2Bundle_noInclusion() {
    var ex =
        Assertions.assertThrows(
            BundleParseException.class,
            () -> readBundle("dev/sigstore/samples/bundles/bundle.v2.no.inclusion.sigstore"));
    Assertions.assertEquals("Could not find an inclusion proof", ex.getMessage());
  }

  @Test
  public void readV3Bundle() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle.v3.sigstore");
  }

  @Test
  public void readV3Bundle_noInclusion() {
    var ex =
        Assertions.assertThrows(
            BundleParseException.class,
            () -> readBundle("dev/sigstore/samples/bundles/bundle.v3.no.inclusion.sigstore"));
    Assertions.assertEquals("Could not find an inclusion proof", ex.getMessage());
  }

  @Test
  public void readV3_1Bundle() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle.v3_1.sigstore");
  }

  @Test
  public void readV3_1Bundle_noInclusion() {
    var ex =
        Assertions.assertThrows(
            BundleParseException.class,
            () -> readBundle("dev/sigstore/samples/bundles/bundle.v3_1.no.inclusion.sigstore"));
    Assertions.assertEquals("Could not find an inclusion proof", ex.getMessage());
  }

  @Test
  public void readDSSEBundle() throws Exception {
    var bundle = readBundle("dev/sigstore/samples/bundles/bundle.dsse.sigstore");
    Assertions.assertTrue(bundle.getDsseEnvelope().isPresent());
    var intotoPayload = InTotoPayload.from(bundle.getDsseEnvelope().get());
    Assertions.assertEquals("https://slsa.dev/provenance/v1", intotoPayload.getPredicateType());
  }

  @Test
  public void readBundle_timestamp() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle-with-timestamp.sigstore");
  }

  @Test
  public void readBundle_rekorV2Entry() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore");
  }

  private Bundle readBundle(String resourcePath) throws Exception {
    try (var reader =
        new InputStreamReader(
            Resources.getResource(resourcePath).openStream(), StandardCharsets.UTF_8)) {
      return Bundle.from(reader);
    }
  }
}
