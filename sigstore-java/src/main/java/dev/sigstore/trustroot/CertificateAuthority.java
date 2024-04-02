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

import dev.sigstore.proto.ProtoMutators;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.immutables.value.Value.Immutable;
import org.immutables.value.Value.Lazy;

@Immutable
public abstract class CertificateAuthority {
  public abstract CertPath getCertPath();

  public abstract URI getUri();

  public abstract ValidFor getValidFor();

  public abstract Subject getSubject();

  public boolean isCurrent() {
    return getValidFor().contains(Instant.now());
  }

  @Lazy
  public TrustAnchor asTrustAnchor()
      throws CertificateException, InvalidAlgorithmParameterException {
    var certs = getCertPath().getCertificates();
    X509Certificate fulcioRootObj = (X509Certificate) certs.get(certs.size() - 1);
    TrustAnchor fulcioRootTrustAnchor = new TrustAnchor(fulcioRootObj, null);

    // validate the certificate can be a trust anchor
    new PKIXParameters(Collections.singleton(fulcioRootTrustAnchor));

    return fulcioRootTrustAnchor;
  }

  public static CertificateAuthority from(
      dev.sigstore.proto.trustroot.v1.CertificateAuthority proto) throws CertificateException {
    return ImmutableCertificateAuthority.builder()
        .certPath(ProtoMutators.toCertPath(proto.getCertChain().getCertificatesList()))
        .validFor(ValidFor.from(proto.getValidFor()))
        .uri(URI.create(proto.getUri()))
        .subject(Subject.from(proto.getSubject()))
        .build();
  }

  /**
   * Find a CA by validity time, users of this method will need to then compare the key in the leaf
   * to find the exact CA to validate against
   *
   * @param time the time the CA was expected to be valid (usually tlog entry time)
   * @return a list of CAs that were valid at {@code time}
   */
  public static List<CertificateAuthority> find(List<CertificateAuthority> all, Instant time) {
    return all.stream().filter(ca -> ca.getValidFor().contains(time)).collect(Collectors.toList());
  }
}
