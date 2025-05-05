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

import dev.sigstore.trustroot.Service.Config.Selector;
import java.net.URI;
import java.time.Instant;
import javax.annotation.Nullable;

/**
 * Internal use only: legacy signing config that contains all the necessary information to keep
 * signers working without signing config being available on a TUF repo
 */
public class LegacySigningConfig {

  static final URI REKOR_PUBLIC_GOOD_URI = URI.create("https://rekor.sigstore.dev");
  static final URI REKOR_STAGING_URI = URI.create("https://rekor.sigstage.dev");

  static final URI FULCIO_PUBLIC_GOOD_URI = URI.create("https://fulcio.sigstore.dev");
  static final URI FULCIO_STAGING_URI = URI.create("https://fulcio.sigstage.dev");

  static final URI DEX_PUBLIC_GOOD_URI = URI.create("https://oauth2.sigstore.dev/auth");
  static final URI DEX_STAGING_GOOD_URI = URI.create("https://oauth2.sigstage.dev/auth");

  // TSA not fully configured in prod yet
  // static final URI TSA_PUBLIC_GOOD_URI =
  // URI.create("https://timestamp.sigstore.dev/api/v1/timestamp");
  static final URI TSA_STAGING_URI = URI.create("https://timestamp.sigstage.dev/api/v1/timestamp");

  static SigstoreSigningConfig from(URI fulcioUrl, URI rekorUrl, URI dexUrl, @Nullable URI tsaUrl) {
    var anySelector = ImmutableConfig.builder().selector(Selector.ANY).build();
    var now = ImmutableValidFor.builder().start(Instant.now()).build();
    var signingConfigBuilder =
        ImmutableSigstoreSigningConfig.builder()
            .tLogConfig(anySelector)
            .tsaConfig(anySelector)
            .addCas(ImmutableService.builder().apiVersion(1).url(fulcioUrl).validFor(now).build())
            .addTLogs(ImmutableService.builder().apiVersion(1).url(rekorUrl).validFor(now).build())
            .addOidcProviders(
                ImmutableService.builder().apiVersion(1).url(dexUrl).validFor(now).build());
    if (tsaUrl != null) {
      signingConfigBuilder.addTsas(
          ImmutableService.builder().apiVersion(1).url(tsaUrl).validFor(now).build());
    }
    return signingConfigBuilder.build();
  }

  public static final SigstoreSigningConfig PUBLIC_GOOD =
      from(FULCIO_PUBLIC_GOOD_URI, REKOR_PUBLIC_GOOD_URI, DEX_PUBLIC_GOOD_URI, null);
  public static SigstoreSigningConfig STAGING =
      from(FULCIO_STAGING_URI, REKOR_STAGING_URI, DEX_STAGING_GOOD_URI, TSA_STAGING_URI);
}
