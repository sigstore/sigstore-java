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
import dev.sigstore.proto.common.v1.TimeRange;
import java.time.Instant;
import java.util.Optional;
import org.immutables.value.Value.Immutable;

@Immutable
public abstract class ValidFor {
  public abstract Instant getStart();

  public abstract Optional<Instant> getEnd();

  /** Check if an instant of time is contained within the validity range including the endpoints. */
  public boolean contains(Instant instant) {
    if (instant.isBefore(getStart())) {
      return false;
    }
    if (getEnd().isEmpty()) {
      return true;
    }
    return !instant.isAfter(getEnd().get());
  }

  public static ValidFor from(TimeRange proto) {
    return ImmutableValidFor.builder()
        .start(ProtoMutators.toInstant(proto.getStart()))
        .end(
            proto.hasEnd()
                ? Optional.of(ProtoMutators.toInstant(proto.getEnd()))
                : Optional.empty())
        .build();
  }
}
