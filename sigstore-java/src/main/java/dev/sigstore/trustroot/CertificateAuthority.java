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
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.time.Instant;
import org.immutables.value.Value.Immutable;

@Immutable
public abstract class CertificateAuthority {
  public abstract CertPath getCertPath();

  public abstract URI getUri();

  public abstract ValidFor getValidFor();

  public abstract Subject getSubject();

  public boolean isCurrent() {
    return getValidFor().contains(Instant.now());
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
}
