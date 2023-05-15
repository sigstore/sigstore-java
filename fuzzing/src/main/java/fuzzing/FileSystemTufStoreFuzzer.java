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
import dev.sigstore.tuf.FileSystemTufStore;
import dev.sigstore.tuf.MutableTufStore;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.FileUtils;

public class FileSystemTufStoreFuzzer {
  private static MutableTufStore mts;
  private static Path tempDirectory;

  public static void fuzzerInitialize() {
    try {
      tempDirectory = Files.createTempDirectory("sigstore-oss-fuzz");
      mts = FileSystemTufStore.newFileSystemStore(tempDirectory);
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
      int[] intArray = data.consumeInts(data.consumeInt(1, 10));
      String string = data.consumeString(data.consumeInt(1, 10));
      byte[] byteArray = data.consumeRemainingAsBytes();

      for (int choice : intArray) {
        switch (choice % 7) {
          case 0:
            mts.loadTrustedRoot();
            break;
          case 1:
            mts.loadTimestamp();
            break;
          case 2:
            mts.loadSnapshot();
            break;
          case 3:
            mts.loadTargets();
            break;
          case 4:
            mts.storeTargetFile(string, byteArray);
            break;
          case 5:
            mts.getTargetFile(string);
            break;
          case 6:
            mts.clearMetaDueToKeyRotation();
            break;
        }
      }
    } catch (IllegalArgumentException | IOException e) {
      // Known exception
    } finally {
      clearTempDirectory();
    }
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
