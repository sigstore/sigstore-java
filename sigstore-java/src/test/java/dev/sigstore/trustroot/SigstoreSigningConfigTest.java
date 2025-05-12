/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.trustroot;

import com.google.common.io.Resources;
import dev.sigstore.trustroot.Service.Config.Selector;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SigstoreSigningConfigTest {

  @Test
  public void testFrom_smokeTest() throws SigstoreConfigurationException, IOException {
    var signingConfig =
        SigstoreSigningConfig.from(
            Resources.getResource("dev/sigstore/trustroot/staging_signing_config.v0.2.json")
                .openStream());

    // simple check on Selector
    Assertions.assertEquals(Selector.ANY, signingConfig.getTLogConfig().getSelector());
    Assertions.assertEquals(Selector.ANY, signingConfig.getTsaConfig().getSelector());

    assertServiceMatches(
        signingConfig.getCas(), "https://fulcio.sigstage.dev", 1, "2022-04-14T21:38:40Z");
    assertServiceMatches(
        signingConfig.getTLogs(), "https://rekor.sigstage.dev", 1, "2021-01-12T11:53:27Z");
    assertServiceMatches(
        signingConfig.getOidcProviders(),
        "https://oauth2.sigstage.dev/auth",
        1,
        "2025-04-16T00:00:00Z");
    assertServiceMatches(
        signingConfig.getTsas(),
        "https://timestamp.sigstage.dev/api/v1/timestamp",
        1,
        "2025-04-09T00:00:00Z");
    // check configs
  }

  void assertServiceMatches(
      List<Service> serviceList, String url, int apiVersion, String startDate) {
    Assertions.assertEquals(1, serviceList.size());
    Service service = serviceList.get(0);
    Assertions.assertEquals(url, service.getUrl().toString());
    Assertions.assertEquals(apiVersion, service.getApiVersion());
    Assertions.assertEquals(Instant.parse(startDate), service.getValidFor().getStart());
  }
}
