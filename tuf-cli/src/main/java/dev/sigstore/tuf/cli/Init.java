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
package dev.sigstore.tuf.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

@Command(name = "init", description = "initialize a local tuf repo")
public class Init implements Callable<Integer> {

  @Parameters(arity = "1", paramLabel = "<TRUSTED_ROOT>")
  Path trustedRoot;

  @ParentCommand private Tuf tufCommand;

  @Override
  public Integer call() throws Exception {
    var metadataDir = tufCommand.getMetadataDir();

    if (!Files.isRegularFile(trustedRoot)) {
      throw new IllegalArgumentException(trustedRoot + " is not a regular file");
    }
    if (Files.exists(metadataDir)) {
      if (!Files.isDirectory(metadataDir)) {
        throw new IllegalArgumentException(metadataDir + " is not a directory");
      }
    } else {
      Files.createDirectories(metadataDir);
    }

    Files.copy(trustedRoot, metadataDir.resolve("root.json"));
    return 0;
  }
}
