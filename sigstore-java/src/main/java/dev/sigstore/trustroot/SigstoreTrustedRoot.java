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

import com.google.api.client.util.Lists;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.stream.Collectors;
import org.immutables.value.Value.Immutable;

@Immutable
public interface SigstoreTrustedRoot {

  /** A list of certificate authorities associated with this trustroot. */
  List<CertificateAuthority> getCAs();

  /** A list of binary transparency logs associated with this trustroot. */
  List<TransparencyLog> getTLogs();

  /** A list of certificate transparency logs associated with this trustroot. */
  List<TransparencyLog> getCTLogs();

  /** Create an instance from a parsed proto definition of a trustroot. */
  static SigstoreTrustedRoot from(TrustedRoot proto) throws CertificateException {
    List<CertificateAuthority> cas = Lists.newArrayList();
    for (var certAuthority : proto.getCertificateAuthoritiesList()) {
      cas.add(CertificateAuthority.from(certAuthority));
    }

    List<TransparencyLog> tlogs =
        proto.getTlogsList().stream().map(TransparencyLog::from).collect(Collectors.toList());

    List<TransparencyLog> ctlogs =
        proto.getCtlogsList().stream().map(TransparencyLog::from).collect(Collectors.toList());

    return ImmutableSigstoreTrustedRoot.builder().cAs(cas).tLogs(tlogs).cTLogs(ctlogs).build();
  }
}
