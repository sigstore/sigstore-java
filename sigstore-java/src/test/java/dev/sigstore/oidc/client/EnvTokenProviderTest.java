/*
 * Copyright 2026 The Sigstore Authors.
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
package dev.sigstore.oidc.client;

import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EnvTokenProviderTest {

  @Test
  public void isEnabled_true() {
    var provider = EnvTokenProvider.of();
    var env = Map.of(EnvTokenProvider.ENV_VAR_NAME, "some-token");
    Assertions.assertTrue(provider.isEnabled(env));
  }

  @Test
  public void isEnabled_false() {
    var provider = EnvTokenProvider.of();
    Assertions.assertFalse(provider.isEnabled(Map.of()));
  }

  @Test
  public void getTokenString_present() throws Exception {
    var provider = EnvTokenProvider.of();
    var env = Map.of(EnvTokenProvider.ENV_VAR_NAME, "some-token");
    Assertions.assertEquals("some-token", provider.getTokenString(env));
  }

  @Test
  public void getTokenString_missing() {
    var provider = EnvTokenProvider.of();
    var env = Map.of("OTHER_ENV_VAR", "some-token");
    var exception =
        Assertions.assertThrows(
            IllegalStateException.class,
            () -> {
              provider.getTokenString(env);
            });
    Assertions.assertEquals(EnvTokenProvider.ENV_VAR_NAME + " was not set", exception.getMessage());
  }
}
