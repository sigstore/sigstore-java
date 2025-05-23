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
package dev.sigstore;

import com.google.common.base.Preconditions;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@FunctionalInterface
public interface SigningConfigProvider {

  SigstoreSigningConfig get() throws SigstoreConfigurationException;

  static SigningConfigProvider from(SigstoreTufClient.Builder tufClientBuilder) {
    Preconditions.checkNotNull(tufClientBuilder);
    return () -> {
      try {
        SigstoreTufClient tufClient = tufClientBuilder.build();
        tufClient.update();
        return tufClient.getSigstoreSigningConfig();
      } catch (IOException ex) {
        throw new SigstoreConfigurationException(
            "Could not initialize signing config from provided tuf client", ex);
      }
    };
  }

  // Temporary while the tuf repos catches up, this will still fail if the remove TUF isn't
  // available to check for signing config
  static SigningConfigProvider fromOrDefault(
      SigstoreTufClient.Builder tufClientBuilder, SigstoreSigningConfig defaultConfig) {
    Preconditions.checkNotNull(tufClientBuilder);
    return () -> {
      try {
        var tufClient = tufClientBuilder.build();
        tufClient.update();
        var fromTuf = tufClient.getSigstoreSigningConfig();
        return fromTuf == null ? defaultConfig : fromTuf;
      } catch (IOException ex) {
        throw new SigstoreConfigurationException(
            "Could not initialize signing config from provided tuf client", ex);
      }
    };
  }

  static SigningConfigProvider from(Path signingConfig) {
    Preconditions.checkNotNull(signingConfig);
    return () -> {
      try {
        return SigstoreSigningConfig.from(Files.newInputStream(signingConfig));
      } catch (IOException ex) {
        throw new SigstoreConfigurationException(
            "Could not initialize signing config from " + signingConfig, ex);
      }
    };
  }
}
