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
import dev.sigstore.tuf.model.Root;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import javax.annotation.Nullable;

/** Uses a local file system directory to store the trusted TUF metadata. */
public class FileSystemTufStore implements TufLocalStore {

  private static final String ROOT_FILE_NAME = "root.json";
  private static final String SNAPSHOT_FILE_NAME = "snapshot.json";
  private static final String TIMESTAMP_FILE_NAME = "timestamp.json";
  private Path repoBaseDir;
  private Root trustedRoot;

  @VisibleForTesting
  FileSystemTufStore(Path repoBaseDir, @Nullable Root trustedRoot) {
    this.repoBaseDir = repoBaseDir;
    this.trustedRoot = trustedRoot;
  }

  static TufLocalStore newFileSystemStore(Path repoBaseDir) throws IOException {
    Path rootFile = repoBaseDir.resolve(ROOT_FILE_NAME);
    Root trustedRoot = null;
    if (rootFile.toFile().exists()) {
      trustedRoot = GSON.get().fromJson(Files.readString(rootFile), Root.class);
    }
    return new FileSystemTufStore(repoBaseDir, trustedRoot);
  }

  @Override
  public Optional<Root> getTrustedRoot() {
    return Optional.ofNullable(trustedRoot);
  }

  @Override
  public void setTrustedRoot(Root root) throws IOException {
    if (root == null) {
      throw new NullPointerException("Root should not be null");
    }
    Path rootPath = repoBaseDir.resolve(ROOT_FILE_NAME);
    if (trustedRoot != null) {
      // back it up
      Files.move(
          rootPath,
          repoBaseDir.resolve(trustedRoot.getSignedMeta().getVersion() + "." + ROOT_FILE_NAME));
    }
    trustedRoot = root;
    try (FileWriter fileWriter = new FileWriter(rootPath.toFile())) {
      fileWriter.write(GSON.get().toJson(trustedRoot));
    }
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
