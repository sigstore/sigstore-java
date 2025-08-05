/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.cli;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;

public class ConformanceServer {

  private static final Gson GSON = new Gson();

  private static class ExecuteRequest {
    String cwd;
    String[] args;
  }

  public static void main(String[] args) throws Exception {
    int port = 8080;
    Server server = new Server(port);
    server.setHandler(new ConformanceHandler());
    server.start();
    server.join();
  }

  public static class ConformanceHandler extends AbstractHandler {
    @Override
    public void handle(
        String target,
        Request baseRequest,
        HttpServletRequest request,
        HttpServletResponse response)
        throws IOException, ServletException {
      if ("/".equals(target)) {
        handleHealthCheck(response);
        baseRequest.setHandled(true);
      } else if ("/execute".equals(target) && "POST".equals(request.getMethod())) {
        handleExecute(request, response);
        baseRequest.setHandled(true);
      }
    }
  }

  private static void handleExecute(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    ExecuteRequest executeRequest;
    try (InputStream is = request.getInputStream()) {
      String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
      executeRequest = GSON.fromJson(requestBody, ExecuteRequest.class);
    }

    // Tests should not be run in parallel, to ensure orderly input/output
    PrintStream originalOut = System.out;
    PrintStream originalErr = System.err;

    ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    ByteArrayOutputStream errContent = new ByteArrayOutputStream();

    try (PrintStream outPs = new PrintStream(outContent, true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(errContent, true, StandardCharsets.UTF_8)) {
      System.setOut(outPs);
      System.setErr(errPs);

      Path cwd = Paths.get(executeRequest.cwd);
      java.util.List<String> resolvedArgs = new java.util.ArrayList<>();

      for (int i = 0; i < executeRequest.args.length; i++) {
        String arg = executeRequest.args[i];

        if (arg.equals("--bundle") && i + 1 < executeRequest.args.length) {
          resolvedArgs.add(arg);
          String filePath = executeRequest.args[++i];
          resolvedArgs.add(cwd.resolve(filePath).toAbsolutePath().toString());
        } else if (i == executeRequest.args.length - 1 && !arg.startsWith("-")) {
          if (arg.contains(":")) {
            resolvedArgs.add(arg);
          } else {
            resolvedArgs.add(cwd.resolve(arg).toAbsolutePath().toString());
          }
        } else {
          resolvedArgs.add(arg);
        }
      }

      int exitCode =
          new picocli.CommandLine(new Sigstore()).execute(resolvedArgs.toArray(new String[0]));

      Map<String, Object> responseMap =
          Map.of(
              "stdout", outContent.toString(StandardCharsets.UTF_8),
              "stderr", errContent.toString(StandardCharsets.UTF_8),
              "exitCode", exitCode);
      String jsonResponse = GSON.toJson(responseMap);

      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("application/json");
      byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
      response.setContentLength(responseBytes.length);

      try (OutputStream os = response.getOutputStream()) {
        os.write(responseBytes);
      }
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
  }

  private static void handleHealthCheck(HttpServletResponse response) throws IOException {
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().println("OK");
  }
}
