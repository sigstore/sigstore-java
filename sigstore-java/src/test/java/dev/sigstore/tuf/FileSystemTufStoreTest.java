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

  @Test
  void newFileSystemStore_empty(@TempDir Path repoBase) throws IOException {
    TufLocalStore tufLocalStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertFalse(tufLocalStore.loadTrustedRoot().isPresent());
  }

  @Test
  void newFileSystemStore_hasRepo(@TempDir Path repoBase) throws IOException {
    String repoName = "remote-repo-prod";
    TestResources.setupRepoFiles(repoName, repoBase, "root.json");
    TufLocalStore tufLocalStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertTrue(tufLocalStore.loadTrustedRoot().isPresent());
  }

  @Test
  void setTrustedRoot_noPrevious(@TempDir Path repoBase) throws IOException {
    TufLocalStore tufLocalStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertFalse(repoBase.resolve("root.json").toFile().exists());
    tufLocalStore.storeTrustedRoot(TestResources.loadRoot(TestResources.CLIENT_TRUSTED_ROOT));
    assertEquals(1, repoBase.toFile().list().length);
    assertTrue(repoBase.resolve("root.json").toFile().exists());
  }

  @Test
  void setTrustedRoot_backupPerformed(@TempDir Path repoBase) throws IOException {
    String repoName = "remote-repo-prod";
    TestResources.setupRepoFiles(repoName, repoBase, "root.json");
    TufLocalStore tufLocalStore = FileSystemTufStore.newFileSystemStore(repoBase);
    int version = tufLocalStore.loadTrustedRoot().get().getSignedMeta().getVersion();
    assertFalse(repoBase.resolve(version + ".root.json").toFile().exists());
    tufLocalStore.storeTrustedRoot(TestResources.loadRoot(TestResources.CLIENT_TRUSTED_ROOT));
    assertTrue(repoBase.resolve(version + ".root.json").toFile().exists());
  }

  @Test
  void clearMetaDueToKeyRotation(@TempDir Path repoBase) throws IOException {
    String repoName = "remote-repo-prod";
    TestResources.setupRepoFiles(repoName, repoBase, "snapshot.json", "timestamp.json");
    TufLocalStore tufLocalStore = FileSystemTufStore.newFileSystemStore(repoBase);
    assertTrue(repoBase.resolve("snapshot.json").toFile().exists());
    assertTrue(repoBase.resolve("timestamp.json").toFile().exists());
    tufLocalStore.clearMetaDueToKeyRotation();
    assertFalse(repoBase.resolve("snapshot.json").toFile().exists());
    assertFalse(repoBase.resolve("timestamp.json").toFile().exists());
  }
}
