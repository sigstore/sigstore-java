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

import dev.sigstore.proto.trustroot.v1.TransparencyLogInstance;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.immutables.value.Value.Immutable;

@Immutable
public interface TransparencyLog {
  URI getBaseUrl();

  String getHashAlgorithm();

  LogId getLogId();

  PublicKey getPublicKey();

  // TODO (https://github.com/sigstore/sigstore-java/issues/987) move off of log_id
  @SuppressWarnings("deprecation")
  static TransparencyLog from(TransparencyLogInstance proto) {
    return ImmutableTransparencyLog.builder()
        .baseUrl(URI.create(proto.getBaseUrl()))
        .hashAlgorithm(proto.getHashAlgorithm().name())
        .logId(LogId.from(proto.getLogId()))
        .publicKey(PublicKey.from(proto.getPublicKey()))
        .build();
  }

  /**
   * Find a log by logId.
   *
   * @param logId the logId of the log
   * @return the first log with matching {@code logId}
   */
  static Optional<TransparencyLog> find(List<TransparencyLog> all, byte[] logId) {
    return all.stream().filter(tl -> Arrays.equals(tl.getLogId().getKeyId(), logId)).findAny();
  }

  /**
   * Find a log by validity time and logId. This will find the first log with matching log id that
   * was valid at the time.
   *
   * @param logId the logId of the log
   * @param time the time the log was expected to be valid
   * @return the first log that was valid at {@code time} with logId {@code logId}
   */
  static Optional<TransparencyLog> find(List<TransparencyLog> all, byte[] logId, Instant time) {
    return all.stream()
        .filter(tl -> Arrays.equals(tl.getLogId().getKeyId(), logId))
        .filter(tl -> tl.getPublicKey().getValidFor().contains(time))
        .findAny();
  }
}
