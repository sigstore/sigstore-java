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
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;
import org.immutables.value.Value.Immutable;

@Immutable
@Value.Style(depluralize = true)
public abstract class TransparencyLogs implements Iterable<TransparencyLog> {

  public abstract List<TransparencyLog> getTransparencyLogs();

  @Derived
  public int size() {
    return getTransparencyLogs().size();
  }

  @Derived
  public List<TransparencyLog> all() {
    return getTransparencyLogs();
  }

  public TransparencyLog current() {
    var current =
        getTransparencyLogs().stream()
            .filter(tl -> tl.getPublicKey().getValidFor().getEnd().isEmpty())
            .collect(Collectors.toList());
    if (current.size() == 0) {
      throw new IllegalStateException("Trust root contains no current transparency logs");
    }
    if (current.size() > 1) {
      throw new IllegalStateException(
          "Trust root contains multiple current transparency logs (" + current.size() + ")");
    }
    return current.get(0);
  }

  public Optional<TransparencyLog> find(byte[] logId, Instant time) {
    return getTransparencyLogs().stream()
        .filter(tl -> Arrays.equals(tl.getLogId().getKeyId(), logId))
        .filter(tl -> tl.getPublicKey().getValidFor().contains(time))
        .findAny();
  }

  @Override
  public Iterator<TransparencyLog> iterator() {
    return getTransparencyLogs().iterator();
  }
}
