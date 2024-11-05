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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Uses a local file system directory to store the trusted TUF metadata. */
public class FileSystemTufStore implements MetaStore, TargetStore {

  private final Path repoBaseDir;
  private final Path targetsCache;

  @VisibleForTesting
  FileSystemTufStore(Path repoBaseDir, Path targetsCache) {
    this.repoBaseDir = repoBaseDir;
    this.targetsCache = targetsCache;
  }

  public static FileSystemTufStore newFileSystemStore(Path repoBaseDir) throws IOException {
    if (!Files.isDirectory(repoBaseDir)) {
      throw new IllegalArgumentException(repoBaseDir + " must be a file system directory.");
    }
    Path defaultTargetsCache = repoBaseDir.resolve("targets");
    if (!Files.exists(defaultTargetsCache)) {
      Files.createDirectory(defaultTargetsCache);
    }
    return newFileSystemStore(repoBaseDir, defaultTargetsCache);
  }

  public static FileSystemTufStore newFileSystemStore(Path repoBaseDir, Path targetsCache) {
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
    return "Meta: " + repoBaseDir.toAbsolutePath() + ", Targets:" + targetsCache.toAbsolutePath();
  }

  @Override
  public void writeTarget(String targetName, byte[] targetContents) throws IOException {
    Files.write(targetsCache.resolve(targetName), targetContents);
  }

  @Override
  public byte[] readTarget(String targetName) throws IOException {
    return Files.readAllBytes(targetsCache.resolve(targetName));
  }

  @Override
  public void writeMeta(String roleName, SignedTufMeta<?> meta) throws IOException {
    storeRole(roleName, meta);
  }

  @Override
  public <T extends SignedTufMeta<?>> Optional<T> readMeta(String roleName, Class<T> tClass)
      throws IOException {
    Path roleFile = repoBaseDir.resolve(roleName + ".json");
    if (!roleFile.toFile().exists()) {
      return Optional.empty();
    }
    return Optional.of(GSON.get().fromJson(Files.readString(roleFile), tClass));
  }

  <T extends SignedTufMeta<?>> void storeRole(String roleName, T role) throws IOException {
    try (BufferedWriter fileWriter =
        Files.newBufferedWriter(repoBaseDir.resolve(roleName + ".json"))) {
      GSON.get().toJson(role, fileWriter);
    }
  }

  @Override
  public void clearMeta(String role) throws IOException {
    Path metaFile = repoBaseDir.resolve(role + ".json");
    if (Files.isRegularFile(metaFile)) {
      Files.delete(metaFile);
    }
  }
}
