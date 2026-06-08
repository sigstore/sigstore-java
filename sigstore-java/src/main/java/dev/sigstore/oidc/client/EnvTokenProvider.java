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

public class EnvTokenProvider implements TokenStringOidcClient.TokenStringProvider {
  static final String ENV_VAR_NAME = "SIGSTORE_JAVA_ID_TOKEN";

  static EnvTokenProvider of() {
    return new EnvTokenProvider();
  }

  private EnvTokenProvider() {}

  @Override
  public boolean isEnabled(Map<String, String> env) {
    return env.containsKey(ENV_VAR_NAME);
  }

  @Override
  public String getTokenString(Map<String, String> env) throws Exception {
    var token = env.get(ENV_VAR_NAME);
    if (token == null) {
      throw new IllegalStateException(ENV_VAR_NAME + " was not set");
    }
    return token;
  }
}
