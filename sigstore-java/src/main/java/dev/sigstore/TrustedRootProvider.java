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
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@FunctionalInterface
public interface TrustedRootProvider {

  SigstoreTrustedRoot get()
      throws InvalidAlgorithmParameterException, CertificateException, InvalidKeySpecException,
          NoSuchAlgorithmException, IOException, InvalidKeyException;

  static TrustedRootProvider from(SigstoreTufClient.Builder tufClientBuilder) {
    Preconditions.checkNotNull(tufClientBuilder);
    return () -> {
      var tufClient = tufClientBuilder.build();
      tufClient.update();
      return tufClient.getSigstoreTrustedRoot();
    };
  }

  static TrustedRootProvider from(Path trustedRoot) {
    Preconditions.checkNotNull(trustedRoot);
    return () -> {
      var trustedRootBuilder = TrustedRoot.newBuilder();
      JsonFormat.parser()
          .merge(Files.readString(trustedRoot, StandardCharsets.UTF_8), trustedRootBuilder);
      return SigstoreTrustedRoot.from(trustedRootBuilder.build());
    };
  }
}
