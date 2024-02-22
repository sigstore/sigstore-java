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
import dev.sigstore.KeylessSignature;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class BundleFactoryTest {
  @Test
  public void readV1Bundle() throws Exception {
    readBundle("dev/sigstore/samples/bundles/bundle.v1.sigstore");
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
  public void readDSSEBundle() throws Exception {
    var ex =
        Assertions.assertThrows(
            BundleParseException.class,
            () -> readBundle("dev/sigstore/samples/bundles/bundle.dsse.sigstore"));
    Assertions.assertEquals(
        "DSSE envelope signatures are not supported by this client", ex.getMessage());
  }

  private KeylessSignature readBundle(String resourcePath)
      throws IOException, BundleParseException {
    try (var reader =
        new InputStreamReader(
            Resources.getResource(resourcePath).openStream(), StandardCharsets.UTF_8)) {
      return BundleFactory.readBundle(reader);
    }
  }
}
