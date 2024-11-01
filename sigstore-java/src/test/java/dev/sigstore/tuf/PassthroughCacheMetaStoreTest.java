/*
 * Copyright 2024 The Sigstore Authors.
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

import static dev.sigstore.json.GsonSupplier.GSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.RootRole;
import dev.sigstore.tuf.model.Timestamp;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PassthroughCacheMetaStoreTest {

  @TempDir Path localStore;
  private FileSystemTufStore fileSystemTufStore;
  private PassthroughCacheMetaStore passthroughCacheMetaStore;

  private static Root root;
  private static Timestamp timestamp;

  @BeforeAll
  public static void readAllMeta() throws IOException, URISyntaxException {
    Path rootResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/root.json").getPath());
    root = GSON.get().fromJson(Files.newBufferedReader(rootResource), Root.class);
    Path timestampResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/timestamp.json").getPath());
    timestamp = GSON.get().fromJson(Files.newBufferedReader(timestampResource), Timestamp.class);
  }

  @BeforeEach
  public void setup() throws IOException {
    fileSystemTufStore = FileSystemTufStore.newFileSystemStore(localStore);
    passthroughCacheMetaStore =
        PassthroughCacheMetaStore.newPassthroughMetaCache(fileSystemTufStore);
  }

  @Test
  public void root_test() throws Exception {
    assertTrue(fileSystemTufStore.readMeta(RootRole.ROOT, Root.class).isEmpty());
    assertTrue(passthroughCacheMetaStore.readMeta(RootRole.ROOT, Root.class).isEmpty());

    passthroughCacheMetaStore.writeRoot(root);

    assertEquals(root, fileSystemTufStore.readMeta(RootRole.ROOT, Root.class).get());
    assertEquals(root, passthroughCacheMetaStore.readMeta(RootRole.ROOT, Root.class).get());
  }

  @Test
  public void root_canInitFromDisk() throws Exception {
    assertTrue(fileSystemTufStore.readMeta(RootRole.ROOT, Root.class).isEmpty());
    assertTrue(passthroughCacheMetaStore.readMeta(RootRole.ROOT, Root.class).isEmpty());

    try (BufferedWriter fileWriter = Files.newBufferedWriter(localStore.resolve("root.json"))) {
      GSON.get().toJson(root, fileWriter);
    }

    assertEquals(root, fileSystemTufStore.readMeta(RootRole.ROOT, Root.class).get());
    assertEquals(root, passthroughCacheMetaStore.readMeta(RootRole.ROOT, Root.class).get());
  }

  @Test
  public void meta_test() throws Exception {
    // root uses special handling for writing, but the rest of them don't, so we just test
    // timestamp here arbitrarily
    assertTrue(fileSystemTufStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).isEmpty());
    assertTrue(passthroughCacheMetaStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).isEmpty());

    passthroughCacheMetaStore.writeMeta(RootRole.TIMESTAMP, timestamp);

    assertEquals(timestamp, fileSystemTufStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).get());
    assertEquals(
        timestamp, passthroughCacheMetaStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).get());
  }

  @Test
  public void timestamp_canInitFromDisk() throws Exception {
    assertTrue(fileSystemTufStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).isEmpty());
    assertTrue(passthroughCacheMetaStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).isEmpty());

    try (BufferedWriter fileWriter =
        Files.newBufferedWriter(localStore.resolve("timestamp.json"))) {
      GSON.get().toJson(timestamp, fileWriter);
    }

    assertEquals(timestamp, fileSystemTufStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).get());
    assertEquals(
        timestamp, passthroughCacheMetaStore.readMeta(RootRole.TIMESTAMP, Timestamp.class).get());
  }
}