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
package dev.sigstore.trustroot;

import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import java.security.cert.CertificateException;
import org.immutables.value.Value.Immutable;

@Immutable
public interface SigstoreTrustedRoot {

  /** A list of certificate authorities associated with this trustroot. */
  CertificateAuthorities getCAs();

  /** A list of binary transparency logs associated with this trustroot. */
  TransparencyLogs getTLogs();

  /** A list of certificate transparency logs associated with this trustroot. */
  TransparencyLogs getCTLogs();

  /** Create an instance from a parsed proto definition of a trustroot. */
  static SigstoreTrustedRoot from(TrustedRoot proto) throws CertificateException {
    var certificateAuthoritiesBuilder = ImmutableCertificateAuthorities.builder();
    for (var certAuthority : proto.getCertificateAuthoritiesList()) {
      certificateAuthoritiesBuilder.addCertificateAuthority(
          CertificateAuthority.from(certAuthority));
    }

    var tlogsBuilder = ImmutableTransparencyLogs.builder();
    proto.getTlogsList().stream()
        .map(TransparencyLog::from)
        .forEach(tlogsBuilder::addTransparencyLog);

    var ctlogsBuilder = ImmutableTransparencyLogs.builder();
    proto.getCtlogsList().stream()
        .map(TransparencyLog::from)
        .forEach(ctlogsBuilder::addTransparencyLog);

    return ImmutableSigstoreTrustedRoot.builder()
        .cAs(certificateAuthoritiesBuilder.build())
        .tLogs(tlogsBuilder.build())
        .cTLogs(ctlogsBuilder.build())
        .build();
  }
}
