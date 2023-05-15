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
package dev.sigstore.rekor.client;

import com.google.common.io.Resources;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RekorTypesTest {

  private RekorEntry fromResource(String path) throws Exception {
    var rekorResponse = Resources.toString(Resources.getResource(path), StandardCharsets.UTF_8);

    return RekorResponse.newRekorResponse(new URI("https://not.used.com"), rekorResponse)
        .getEntry();
  }

  @Test
  public void getHashedRekord_pass() throws Exception {
    var entry = fromResource("dev/sigstore/samples/rekor-response/valid/response.json");

    var hashedRekord = RekorTypes.getHashedRekord(entry);
    Assertions.assertNotNull(hashedRekord);
  }

  @Test
  public void getHashedRekord_badType() throws Exception {
    var entry = fromResource("dev/sigstore/samples/rekor-response/valid/jar-response.json");

    var exception =
        Assertions.assertThrows(RekorTypeException.class, () -> RekorTypes.getHashedRekord(entry));
    Assertions.assertEquals(
        "Expecting type hashedrekord:0.0.1, but found jar:0.0.1", exception.getMessage());
  }
}
