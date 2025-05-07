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
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@FunctionalInterface
public interface SigningConfigProvider {

  SigstoreSigningConfig get()
      throws InvalidAlgorithmParameterException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, IOException, InvalidKeyException,
          SigstoreConfigurationException;

  static SigningConfigProvider from(SigstoreTufClient.Builder tufClientBuilder) {
    Preconditions.checkNotNull(tufClientBuilder);
    return () -> {
      var tufClient = tufClientBuilder.build();
      tufClient.update();
      return tufClient.getSigstoreSigningConfig();
    };
  }

  static SigningConfigProvider from(Path signingConfig) {
    Preconditions.checkNotNull(signingConfig);
    return () -> SigstoreSigningConfig.from(Files.newInputStream(signingConfig));
  }
}
