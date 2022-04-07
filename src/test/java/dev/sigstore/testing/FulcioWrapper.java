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
package dev.sigstore.testing;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * A test fixture to start fulcio from an executable on the system path. This requires fulcio to be
 * installed, do something like go install github.com/sigstore/fulcio
 */
public class FulcioWrapper {

  private final Process fulcioProcess;

  private FulcioWrapper(Process p) {
    this.fulcioProcess = p;
  }

  public static FulcioWrapper startNewServer(File config, String ctLogUrl)
      throws IOException, InterruptedException {
    var pb = new ProcessBuilder();
    var fulcioEnv = System.getenv("FULCIO_BINARY");
    var fulcioCmd = fulcioEnv == null ? "fulcio" : fulcioEnv;
    var ctLogOpt = ctLogUrl == null ? "--ct-log-url=" : "--ct-log-url=" + ctLogUrl;
    pb.command(
        fulcioCmd,
        "serve",
        "--port",
        "5555",
        "--ca",
        "ephemeralca",
        ctLogOpt,
        "--config-path",
        config.getAbsolutePath());
    pb.redirectErrorStream(true);
    pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    var fp = pb.start();
    Thread.sleep(1000); // wait for the server to come up
    return new FulcioWrapper(fp);
  }

  public void shutdown() throws Exception {
    // forcible kill fulcio and all it's subprocesses
    fulcioProcess.destroyForcibly();
    fulcioProcess.waitFor();
    Thread.sleep(1000); // give the server a chance to shutdown
  }

  public URI getURI() {
    return URI.create("http://localhost:5555");
  }
}
