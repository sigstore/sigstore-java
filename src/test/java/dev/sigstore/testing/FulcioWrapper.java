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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.extension.*;

/**
 * A test fixture to start fulcio from an executable on the system path. This requires fulcio to be
 * installed, do something like go install github.com/sigstore/fulcio.
 *
 * <p>It will pick up config for a ctLog (via FakeCTLogServer) using the per test storage item
 * CTLOGURL. It will pick up an issuer for fulcio (via MockOAuth2ServerExtension) using the per test
 * storage item MOCK_OAUTH_ISSUER.
 */
public class FulcioWrapper implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

  private Process fulcioProcess;
  private Path fulcioLog;
  private Path fulcioConfig;

  public URI getURI() {
    return URI.create("http://localhost:5555");
  }

  private Path createConfig(String issuer) throws IOException {
    fulcioConfig = Files.createTempFile("fulcio-config", ".json");
    Files.writeString(
        fulcioConfig,
        String.format(
            "{\"OIDCIssuers\":{ \"%s\": { \"IssuerURL\": \"%s\", \"ClientID\": \"sigstore\", \"Type\": \"email\"}}}",
            issuer, issuer));
    return fulcioConfig;
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    // forcible kill fulcio and all it's subprocesses
    fulcioProcess.destroyForcibly();
    fulcioProcess.waitFor();
    System.out.println(Files.readString(fulcioLog));
    Files.deleteIfExists(fulcioLog);
    Files.deleteIfExists(fulcioConfig);
    Thread.sleep(1000); // give the server a chance to shutdown
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    fulcioLog = Files.createTempFile("fulcio-log", ".txt");
    var ns = ExtensionContext.Namespace.create(context.getTestMethod().orElseThrow().toString());
    String ctLogUrl = context.getStore(ns).get("CTLOGURL", String.class);
    String oauthIssuer = context.getStore(ns).get("MOCK_OAUTH_ISSUER", String.class);
    var config = createConfig(oauthIssuer);
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
        config.toAbsolutePath().toString());
    pb.redirectErrorStream(true);
    pb.redirectOutput(ProcessBuilder.Redirect.to(fulcioLog.toFile()));
    fulcioProcess = pb.start();
    Thread.sleep(1000); // wait for the server to come up
  }

  @Override
  public boolean supportsParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return (parameterContext.getParameter().getType() == FulcioWrapper.class);
  }

  @Override
  public Object resolveParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return this;
  }
}
