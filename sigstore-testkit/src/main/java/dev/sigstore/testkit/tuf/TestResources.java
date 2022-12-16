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
package dev.sigstore.testkit.tuf;

import com.google.common.io.Resources;
import dev.sigstore.json.GsonSupplier;
import dev.sigstore.tuf.model.Root;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TestResources {

  public static final Path UPDATER_REAL_TRUSTED_ROOT =
      Path.of(Resources.getResource("dev/sigstore/tuf/real/trusted-root.json").getPath());
  public static final Path UPDATER_SYNTHETIC_TRUSTED_ROOT =
      Path.of(Resources.getResource("dev/sigstore/tuf/synthetic/trusted-root.json").getPath());

  // get the child folder and retrieve the parent to avoid resource loader finding the
  // dev/sigstore/tuf folder in the classes/ dir.
  // TODO(patrick@chainguard.dev): cleanup after we move the v5 root into main.
  public static final Path TUF_TEST_DATA_DIRECTORY =
      Path.of(Resources.getResource("dev/sigstore/tuf/real").getPath()).getParent();

  public static void setupRepoFiles(String repoName, Path destinationDir, String... files)
      throws IOException {
    for (String file : files) {
      Files.copy(
          TestResources.TUF_TEST_DATA_DIRECTORY.resolve(repoName).resolve(file),
          destinationDir.resolve(file));
    }
  }

  public static Root loadRoot(Path rootPath) throws IOException {
    return GsonSupplier.GSON.get().fromJson(Files.readString(rootPath), Root.class);
  }
}
