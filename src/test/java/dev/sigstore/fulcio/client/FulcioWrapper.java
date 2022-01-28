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
package dev.sigstore.fulcio.client;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * A test fixture to start fulcio from an executable on the system path. This requires fulcio to be
 * installed, do something like go install github.com/sigstore/fulcio
 */
public class FulcioWrapper implements AutoCloseable {

  private final Process p;

  private FulcioWrapper(Process p) {
    this.p = p;
  }

  public static FulcioWrapper startNewServer(File config, String ctLogUrl) throws IOException {
    ProcessBuilder pb = new ProcessBuilder();
    String fulcioEnv = System.getenv("FULCIO_BINARY");
    String fulcioCmd = fulcioEnv == null ? "fulcio" : fulcioEnv;
    pb.command(
        fulcioCmd,
        "serve",
        "--port",
        "5555",
        "--ca",
        "ephemeralca",
        "--ct-log-url",
        ctLogUrl,
        "--config-path",
        config.getAbsolutePath());
    pb.redirectErrorStream(true);
    pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    Process p = pb.start();
    return new FulcioWrapper(p);
  }

  @Override
  public void close() {
    p.destroy();
  }

  public URI getURI() {
    return URI.create("http://localhost:5555");
  }
}
