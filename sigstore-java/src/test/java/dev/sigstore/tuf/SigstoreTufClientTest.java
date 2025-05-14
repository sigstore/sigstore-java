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
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

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

    assertTrustedRootValid(client.getSigstoreTrustedRoot());
  }

  @Test
  public void testUpdate_publicGoodNoSigningConfigV02() throws Exception {
    var client =
        SigstoreTufClient.builder()
            .usePublicGoodInstance()
            .tufCacheLocation(localStorePath)
            .build();
    client.forceUpdate();

    // TODO: change this when we publish new signing config to public good
    Assertions.assertNull(client.getSigstoreSigningConfig());
  }

  @Test
  public void testUpdate_stagingHasTrustedRootJson() throws Exception {
    var client =
        SigstoreTufClient.builder().useStagingInstance().tufCacheLocation(localStorePath).build();
    client.forceUpdate();

    assertTrustedRootValid(client.getSigstoreTrustedRoot());
  }

  @Test
  public void testUpdate_stagingHasSigningConfigV02() throws Exception {
    var client =
        SigstoreTufClient.builder().useStagingInstance().tufCacheLocation(localStorePath).build();
    client.forceUpdate();

    assertSigningConfigValid(client.getSigstoreSigningConfig());
  }

  private void assertTrustedRootValid(SigstoreTrustedRoot trustedRoot) {
    Assertions.assertNotNull(trustedRoot);

    for (var tlog : trustedRoot.getTLogs()) {
      Assertions.assertDoesNotThrow(() -> tlog.getPublicKey().toJavaPublicKey());
    }

    for (var ctlog : trustedRoot.getCTLogs()) {
      Assertions.assertDoesNotThrow(() -> ctlog.getPublicKey().toJavaPublicKey());
    }
  }

  private void assertSigningConfigValid(SigstoreSigningConfig signingConfig) {
    Assertions.assertNotNull(signingConfig);

    assertNonEmpty(signingConfig.getCas());
    assertNonEmpty(signingConfig.getTsas());
    assertNonEmpty(signingConfig.getTLogs());
    assertNonEmpty(signingConfig.getOidcProviders());
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
    var mockTargetStore = Mockito.mock(TargetStore.class);
    Mockito.when(mockTargetStore.getTargetInputSteam(SigstoreTufClient.TRUST_ROOT_FILENAME))
        .thenAnswer((Answer<InputStream>) invocation -> new ByteArrayInputStream(trustRootBytes));
    Mockito.when(mockUpdater.getTargetStore()).thenReturn(mockTargetStore);

    return mockUpdater;
  }

  private <T> void assertNonEmpty(List<T> list) {
    Assertions.assertNotNull(list);
    Assertions.assertFalse(list.isEmpty());
  }
}
