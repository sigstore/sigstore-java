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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class TransparencyLogsTest {

  @Test
  public void current_missing() {
    Assertions.assertThrows(
        IllegalStateException.class, () -> ImmutableTransparencyLogs.builder().build().current());
  }

  @Test
  public void current_tooMany() {
    var pk = Mockito.mock(PublicKey.class);
    Mockito.when(pk.getValidFor())
        .thenReturn(
            ImmutableValidFor.builder().start(Instant.now().minus(10, ChronoUnit.SECONDS)).build());
    var tlog =
        ImmutableTransparencyLog.builder()
            .logId(Mockito.mock(LogId.class))
            .baseUrl(URI.create("abc"))
            .hashAlgorithm("sha256")
            .publicKey(pk)
            .build();
    Assertions.assertThrows(
        IllegalStateException.class,
        () ->
            ImmutableTransparencyLogs.builder().addTransparencyLogs(tlog, tlog).build().current());
  }
}
