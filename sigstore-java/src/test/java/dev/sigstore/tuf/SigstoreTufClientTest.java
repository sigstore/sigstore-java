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
package dev.sigstore.tuf;

import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

class SigstoreTufClientTest {

  @TempDir Path localStorePath;

  @Test
  public void testUpdate_publicGoodHasTrustedRootJson() throws Exception {
    var client =
        SigstoreTufClient.builder()
            .usePublicGoodInstance()
            .tufCacheLocation(localStorePath)
            .build();
    client.forceUpdate();
    Assertions.assertNotNull(client.getSigstoreTrustedRoot());

    Assertions.assertDoesNotThrow(() -> client.getSigstoreTrustedRoot().getTLogs().current());
    Assertions.assertDoesNotThrow(() -> client.getSigstoreTrustedRoot().getCTLogs().current());
    Assertions.assertDoesNotThrow(() -> client.getSigstoreTrustedRoot().getCAs().current());
  }

  @Test
  public void testUpdate_updateWhenCacheInvalid() throws Exception {
    var mockUpdater = mockUpdater();
    var client = new SigstoreTufClient(mockUpdater, Duration.ofSeconds(2));

    client.update();
    Thread.sleep(3000);
    client.update();
    Mockito.verify(mockUpdater, Mockito.times(2)).update();
  }

  @Test
  public void testUpdate_noUpdateWhenCacheValid() throws Exception {
    var mockUpdater = mockUpdater();
    var client = new SigstoreTufClient(mockUpdater, Duration.ofSeconds(2));

    client.update();
    client.update();
    Mockito.verify(mockUpdater, Mockito.times(1)).update();
  }

  private static Updater mockUpdater() throws IOException {
    var trustRootBytes =
        JsonFormat.printer().print(TrustedRoot.newBuilder()).getBytes(StandardCharsets.UTF_8);
    var mockUpdater = Mockito.mock(Updater.class);
    var mockTufStore = Mockito.mock(MutableTufStore.class);
    Mockito.when(mockTufStore.getTargetFile(SigstoreTufClient.TRUST_ROOT_FILENAME))
        .thenReturn(trustRootBytes);
    Mockito.when(mockUpdater.getLocalStore()).thenReturn(mockTufStore);

    return mockUpdater;
  }
}
