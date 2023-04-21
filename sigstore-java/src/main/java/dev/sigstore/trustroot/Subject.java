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

import dev.sigstore.proto.common.v1.DistinguishedName;
import org.immutables.value.Value.Immutable;

@Immutable
interface Subject {
  String getOrganization();

  String getCommonName();

  static Subject from(DistinguishedName proto) {
    return ImmutableSubject.builder()
        .commonName(proto.getCommonName())
        .organization(proto.getOrganization())
        .build();
  }
}
