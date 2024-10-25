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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import dev.sigstore.tuf.model.Root;
import dev.sigstore.tuf.model.Snapshot;
import dev.sigstore.tuf.model.Targets;
import dev.sigstore.tuf.model.Timestamp;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustedMetaTest {

  @TempDir Path localStore;
  private MutableTufStore tufStore;
  private TrustedMeta trustedMeta;

  private static Root root;
  private static Timestamp timestamp;
  private static Snapshot snapshot;
  private static Targets targets;

  @BeforeAll
  public static void readAllMeta() throws IOException, URISyntaxException {
    Path rootResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/root.json").getPath());
    root = GSON.get().fromJson(Files.newBufferedReader(rootResource), Root.class);
    Path timestampResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/timestamp.json").getPath());
    timestamp = GSON.get().fromJson(Files.newBufferedReader(timestampResource), Timestamp.class);
    Path snapshotResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/snapshot.json").getPath());
    snapshot = GSON.get().fromJson(Files.newBufferedReader(snapshotResource), Snapshot.class);
    Path targetsResource =
        Path.of(Resources.getResource("dev/sigstore/tuf/real/prod/targets.json").getPath());
    targets = GSON.get().fromJson(Files.newBufferedReader(targetsResource), Targets.class);
  }

  @BeforeEach
  public void setup() throws IOException {
    tufStore = FileSystemTufStore.newFileSystemStore(localStore);
    trustedMeta = TrustedMeta.newTrustedMeta(tufStore);
  }

  @Test
  public void root_test() throws Exception {
    assertTrue(tufStore.loadTrustedRoot().isEmpty());
    assertTrue(trustedMeta.findRoot().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getRoot);

    trustedMeta.setRoot(root);

    assertTrue(tufStore.loadTrustedRoot().isPresent());
    assertTrue(trustedMeta.findRoot().isPresent());
    Assertions.assertEquals(root, trustedMeta.getRoot());
  }

  @Test
  public void root_canInitFromDisk() throws Exception {
    assertTrue(tufStore.loadTrustedRoot().isEmpty());
    assertTrue(trustedMeta.findRoot().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getRoot);

    try (BufferedWriter fileWriter = Files.newBufferedWriter(localStore.resolve("root.json"))) {
      GSON.get().toJson(root, fileWriter);
    }

    assertTrue(tufStore.loadTrustedRoot().isPresent());
    assertTrue(trustedMeta.findRoot().isPresent());
    Assertions.assertEquals(root, trustedMeta.getRoot());
  }

  @Test
  public void timestamp_test() throws Exception {
    assertTrue(tufStore.loadTimestamp().isEmpty());
    assertTrue(trustedMeta.findTimestamp().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getTimestamp);

    trustedMeta.setTimestamp(timestamp);

    assertTrue(tufStore.loadTimestamp().isPresent());
    assertTrue(trustedMeta.findTimestamp().isPresent());
    Assertions.assertEquals(timestamp, trustedMeta.getTimestamp());
  }

  @Test
  public void timestamp_canInitFromDisk() throws Exception {
    assertTrue(tufStore.loadTimestamp().isEmpty());
    assertTrue(trustedMeta.findTimestamp().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getTimestamp);

    try (BufferedWriter fileWriter =
        Files.newBufferedWriter(localStore.resolve("timestamp.json"))) {
      GSON.get().toJson(timestamp, fileWriter);
    }

    assertTrue(tufStore.loadTimestamp().isPresent());
    assertTrue(trustedMeta.findTimestamp().isPresent());
    Assertions.assertEquals(timestamp, trustedMeta.getTimestamp());
  }

  @Test
  public void snapshot_test() throws Exception {
    assertTrue(tufStore.loadSnapshot().isEmpty());
    assertTrue(trustedMeta.findSnapshot().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getSnapshot);

    trustedMeta.setSnapshot(snapshot);

    assertTrue(tufStore.loadSnapshot().isPresent());
    assertTrue(trustedMeta.findSnapshot().isPresent());
    Assertions.assertEquals(snapshot, trustedMeta.getSnapshot());
  }

  @Test
  public void snapshot_canInitFromDisk() throws Exception {
    assertTrue(tufStore.loadSnapshot().isEmpty());
    assertTrue(trustedMeta.findSnapshot().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getSnapshot);

    try (BufferedWriter fileWriter = Files.newBufferedWriter(localStore.resolve("snapshot.json"))) {
      GSON.get().toJson(snapshot, fileWriter);
    }

    assertTrue(tufStore.loadSnapshot().isPresent());
    assertTrue(trustedMeta.findSnapshot().isPresent());
    Assertions.assertEquals(snapshot, trustedMeta.getSnapshot());
  }

  @Test
  public void targets_test() throws Exception {
    assertTrue(tufStore.loadTargets().isEmpty());
    assertTrue(trustedMeta.findTargets().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getTargets);

    trustedMeta.setTargets(targets);

    assertTrue(tufStore.loadTargets().isPresent());
    assertTrue(trustedMeta.findTargets().isPresent());
    Assertions.assertEquals(targets, trustedMeta.getTargets());
  }

  @Test
  public void targets_canInitFromDisk() throws Exception {
    assertTrue(tufStore.loadTargets().isEmpty());
    assertTrue(trustedMeta.findTargets().isEmpty());
    Assertions.assertThrows(IllegalStateException.class, trustedMeta::getTargets);

    try (BufferedWriter fileWriter = Files.newBufferedWriter(localStore.resolve("targets.json"))) {
      GSON.get().toJson(targets, fileWriter);
    }

    assertTrue(tufStore.loadTargets().isPresent());
    assertTrue(trustedMeta.findTargets().isPresent());
    Assertions.assertEquals(targets, trustedMeta.getTargets());
  }
}
