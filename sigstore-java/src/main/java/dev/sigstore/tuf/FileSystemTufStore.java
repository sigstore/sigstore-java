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

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.common.annotations.VisibleForTesting;
import dev.sigstore.tuf.model.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Uses a local file system directory to store the trusted TUF metadata. */
public class FileSystemTufStore implements TufLocalStore {

  private static final String ROOT_FILE_NAME = "root.json";
  private static final String SNAPSHOT_FILE_NAME = "snapshot.json";
  private static final String TIMESTAMP_FILE_NAME = "timestamp.json";
  private Path repoBaseDir;
  private Path targetsCache;

  @VisibleForTesting
  FileSystemTufStore(Path repoBaseDir, Path targetsCache) {
    this.repoBaseDir = repoBaseDir;
    this.targetsCache = targetsCache;
  }

  public static TufLocalStore newFileSystemStore(Path repoBaseDir) throws IOException {
    if (!Files.isDirectory(repoBaseDir)) {
      throw new IllegalArgumentException(repoBaseDir + " must be a file system directory.");
    }
    Path defaultTargetsCache = repoBaseDir.resolve("targets");
    Files.createDirectory(defaultTargetsCache);
    return newFileSystemStore(repoBaseDir, defaultTargetsCache);
  }

  static TufLocalStore newFileSystemStore(Path repoBaseDir, Path targetsCache) {
    if (!Files.isDirectory(repoBaseDir)) {
      throw new IllegalArgumentException(repoBaseDir + " must be a file system directory.");
    }
    if (!Files.isDirectory(targetsCache)) {
      throw new IllegalArgumentException(targetsCache + " must be a file system directory.");
    }
    return new FileSystemTufStore(repoBaseDir, targetsCache);
  }

  @Override
  public String getIdentifier() {
    return repoBaseDir.toAbsolutePath().toString();
  }

  @Override
  public Optional<Root> loadTrustedRoot() throws IOException {
    return loadRole(Role.Name.ROOT, Root.class);
  }

  @Override
  public Optional<Timestamp> loadTimestamp() throws IOException {
    return loadRole(Role.Name.TIMESTAMP, Timestamp.class);
  }

  @Override
  public Optional<Snapshot> loadSnapshot() throws IOException {
    return loadRole(Role.Name.SNAPSHOT, Snapshot.class);
  }

  @Override
  public Optional<Targets> loadTargets() throws IOException {
    return loadRole(Role.Name.TARGETS, Targets.class);
  }

  @Override
  public void storeTargetFile(String targetName, byte[] targetContents) throws IOException {
    Files.write(targetsCache.resolve(targetName), targetContents);
  }

  @Override
  public byte[] getTargetFile(String targetName) throws IOException {
    return Files.readAllBytes(targetsCache.resolve(targetName));
  }

  @Override
  public <T extends SignedTufMeta> void storeMeta(T timestamp) throws IOException {
    storeRole(timestamp);
  }

  <T extends SignedTufMeta> Optional<T> loadRole(Role.Name roleName, Class<T> tClass)
      throws IOException {
    Path roleFile = repoBaseDir.resolve(roleName + ".json");
    if (!roleFile.toFile().exists()) {
      return Optional.empty();
    }
    return Optional.of(GSON.get().fromJson(Files.readString(roleFile), tClass));
  }

  <T extends SignedTufMeta> void storeRole(T role) throws IOException {
    try (BufferedWriter fileWriter =
        Files.newBufferedWriter(repoBaseDir.resolve(role.getSignedMeta().getType() + ".json"))) {
      GSON.get().toJson(role, fileWriter);
    }
  }

  @Override
  public void storeTrustedRoot(Root root) throws IOException {
    Optional<Root> trustedRoot = loadTrustedRoot();
    if (trustedRoot.isPresent()) {
      try {
        Files.move(
            repoBaseDir.resolve(ROOT_FILE_NAME),
            repoBaseDir.resolve(
                trustedRoot.get().getSignedMeta().getVersion() + "." + ROOT_FILE_NAME));
      } catch (FileAlreadyExistsException e) {
        // The file is already backed-up. continue.
      }
    }
    storeRole(root);
  }

  @Override
  public void clearMetaDueToKeyRotation() throws IOException {
    File snapshotMetaFile = repoBaseDir.resolve(SNAPSHOT_FILE_NAME).toFile();
    if (snapshotMetaFile.exists()) {
      Files.delete(snapshotMetaFile.toPath());
    }
    File timestampMetaFile = repoBaseDir.resolve(TIMESTAMP_FILE_NAME).toFile();
    if (timestampMetaFile.exists()) {
      Files.delete(timestampMetaFile.toPath());
    }
  }
}
