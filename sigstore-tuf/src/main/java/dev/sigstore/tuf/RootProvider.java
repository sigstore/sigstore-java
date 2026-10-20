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
package dev.sigstore.tuf;

import com.google.common.io.Resources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** An interface for providing the tuf root to a client. */
@FunctionalInterface
public interface RootProvider {
  String get() throws IOException;

  static RootProvider fromResource(String resourceName) {
    return () -> Resources.toString(Resources.getResource(resourceName), StandardCharsets.UTF_8);
  }

  static RootProvider fromFile(Path path) {
    return () -> Files.readString(path);
  }
}
