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

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.security.cert.CertPath;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class CertificateAuthoritiesTest {
  @Test
  public void current_missing() {
    Assertions.assertThrows(
        IllegalStateException.class,
        () -> ImmutableCertificateAuthorities.builder().build().current());
  }

  @Test
  public void current_tooMany() {
    var ca =
        ImmutableCertificateAuthority.builder()
            .certPath(Mockito.mock(CertPath.class))
            .uri(URI.create("abc"))
            .subject(ImmutableSubject.builder().commonName("abc").organization("xyz").build())
            .validFor(
                ImmutableValidFor.builder()
                    .start(Instant.now().minus(10, ChronoUnit.SECONDS))
                    .build())
            .build();
    Assertions.assertThrows(
        IllegalStateException.class,
        () ->
            ImmutableCertificateAuthorities.builder()
                .addCertificateAuthorities(ca, ca)
                .build()
                .current());
  }
}
