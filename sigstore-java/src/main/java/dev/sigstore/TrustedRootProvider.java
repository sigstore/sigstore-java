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
package dev.sigstore;

import com.google.common.base.Preconditions;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@FunctionalInterface
public interface TrustedRootProvider {

  SigstoreTrustedRoot get() throws SigstoreConfigurationException;

  static TrustedRootProvider from(SigstoreTufClient.Builder tufClientBuilder) {
    Preconditions.checkNotNull(tufClientBuilder);
    return () -> {
      try {
        var tufClient = tufClientBuilder.build();
        tufClient.update();
        return tufClient.getSigstoreTrustedRoot();
      } catch (IOException ex) {
        throw new SigstoreConfigurationException(ex);
      }
    };
  }

  static TrustedRootProvider from(Path trustedRoot) {
    Preconditions.checkNotNull(trustedRoot);
    return () -> {
      try (var is = Files.newInputStream(trustedRoot)) {
        return SigstoreTrustedRoot.from(is);
      } catch (IOException ex) {
        throw new SigstoreConfigurationException(ex);
      }
    };
  }
}
