/*
 * Copyright 2022 The Sigstore Authors.
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

import static org.junit.jupiter.api.Assertions.*;

import dev.sigstore.testkit.tuf.TestResources;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileSystemTufStoreTest {

  public static final String PROD_REPO = "real/prod";

  @Test
  void newFileSystemStore_empty(@TempDir Path repoBase) throws IOException {
    MutableTufStore tufStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertFalse(tufStore.loadTrustedRoot().isPresent());
  }

  @Test
  void newFileSystemStore_hasRepo(@TempDir Path repoBase) throws IOException {
    TestResources.setupRepoFiles(PROD_REPO, repoBase, "root.json");
    MutableTufStore tufStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertTrue(tufStore.loadTrustedRoot().isPresent());
  }

  @Test
  void setTrustedRoot_noPrevious(@TempDir Path repoBase) throws IOException {
    MutableTufStore tufStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertFalse(repoBase.resolve("root.json").toFile().exists());
    tufStore.storeTrustedRoot(TestResources.loadRoot(TestResources.UPDATER_REAL_TRUSTED_ROOT));
    assertEquals(2, repoBase.toFile().list().length, "Expect 2: root.json plus the /targets dir.");
    assertTrue(repoBase.resolve("root.json").toFile().exists());
    assertTrue(repoBase.resolve("targets").toFile().isDirectory());
  }

  @Test
  void setTrustedRoot_backupPerformed(@TempDir Path repoBase) throws IOException {
    TestResources.setupRepoFiles(PROD_REPO, repoBase, "root.json");
    MutableTufStore tufStore = FileSystemTufStore.newFileSystemStore(repoBase);
    int version = tufStore.loadTrustedRoot().get().getSignedMeta().getVersion();
    assertFalse(repoBase.resolve(version + ".root.json").toFile().exists());
    tufStore.storeTrustedRoot(TestResources.loadRoot(TestResources.UPDATER_REAL_TRUSTED_ROOT));
    assertTrue(repoBase.resolve(version + ".root.json").toFile().exists());
  }

  @Test
  void clearMetaDueToKeyRotation(@TempDir Path repoBase) throws IOException {
    TestResources.setupRepoFiles(PROD_REPO, repoBase, "snapshot.json", "timestamp.json");
    MutableTufStore tufStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertTrue(repoBase.resolve("snapshot.json").toFile().exists());
    assertTrue(repoBase.resolve("timestamp.json").toFile().exists());
    tufStore.clearMetaDueToKeyRotation();
    assertFalse(repoBase.resolve("snapshot.json").toFile().exists());
    assertFalse(repoBase.resolve("timestamp.json").toFile().exists());
  }
}
