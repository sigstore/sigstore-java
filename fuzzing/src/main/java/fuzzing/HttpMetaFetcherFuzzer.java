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
package fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import dev.sigstore.tuf.FileExceedsMaxLengthException;
import dev.sigstore.tuf.HttpMetaFetcher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.FileUtils;

public class HttpMetaFetcherFuzzer {
  private static Path tempDirectory;

  public static void fuzzerInitialize() {
    try {
      tempDirectory = Files.createTempDirectory("sigstore-oss-fuzz");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    try {
      clearTempDirectory();
      FileUtils.deleteDirectory(tempDirectory.toFile());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer integer = data.consumeInt();
      byte[] byteArray = data.consumeRemainingAsBytes();
      String string = new String(byteArray, StandardCharsets.UTF_8);

      addTempFile(byteArray);

      HttpMetaFetcher fetcher = HttpMetaFetcher.newFetcher(tempDirectory.toUri().toURL());

      fetcher.getRootAtVersion(integer);
      fetcher.fetchResource(string, integer);
    } catch (IllegalArgumentException | FileExceedsMaxLengthException | IOException e) {
      // Known exception
    } finally {
      clearTempDirectory();
    }
  }

  private static void addTempFile(byte[] byteArray) throws IOException {
    File file = File.createTempFile("oss-fuzz-", "-oss-fuzz", tempDirectory.toFile());
    Files.write(file.toPath(), byteArray);
  }

  private static void clearTempDirectory() {
    try {
      for (File file : tempDirectory.toFile().listFiles()) {
        FileUtils.forceDelete(file);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
