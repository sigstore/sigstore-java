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

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;
import org.immutables.value.Value.Immutable;

@Immutable
@Value.Style(
    depluralize = true,
    depluralizeDictionary = {"certificateAuthority:certificateAuthorities"})
public abstract class CertificateAuthorities {

  public abstract List<CertificateAuthority> getCertificateAuthorities();

  @Derived
  public int size() {
    return getCertificateAuthorities().size();
  }

  @Derived
  public List<CertificateAuthority> all() {
    return getCertificateAuthorities();
  }

  /**
   * Find a CA by validity time, users of this method will need to then compare the key in the leaf
   * to find the exact CA to validate against
   *
   * @param time the time the CA was expected to be valid (usually tlog entry time)
   * @return a list of CAs that were valid at {@code time}
   */
  public List<CertificateAuthority> find(Instant time) {
    return getCertificateAuthorities().stream()
        .filter(ca -> ca.getValidFor().getStart().compareTo(time) <= 0)
        .filter(ca -> ca.getValidFor().getEnd().orElse(Instant.now()).compareTo(time) >= 0)
        .collect(Collectors.toList());
  }

  /**
   * Get the one an only current Certificate Authority
   *
   * @return the current active CA
   * @throws IllegalStateException if trust root does not contain exactly one active CA
   */
  public CertificateAuthority current() {
    var current =
        getCertificateAuthorities().stream()
            .filter(CertificateAuthority::isCurrent)
            .collect(Collectors.toList());
    if (current.size() == 0) {
      throw new IllegalStateException("Trust root contains no current certificate authorities");
    }
    if (current.size() > 1) {
      throw new IllegalStateException(
          "Trust root contains multiple current certificate authorities (" + current.size() + ")");
    }
    return current.get(0);
  }
}
