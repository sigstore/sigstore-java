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
package dev.sigstore.tuf.cli;

import com.google.gson.Gson;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.Callback;

public class TufConformanceServer {

  private static final Gson GSON = new Gson();
  private static boolean debug = false;

  private static class ExecuteRequest {
    String[] args;
    String faketime;
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && "--debug".equals(args[0])) {
      debug = true;
    }
    int port = 8080;
    Server server = new Server(port);
    server.setHandler(new TufConformanceHandler());
    server.start();
    server.join();
  }

  public static class TufConformanceHandler extends Handler.Abstract {
    @Override
    public boolean handle(Request request, Response response, Callback callback)
        throws IOException {
      if ("/".equals(request.getHttpURI().getPath())) {
        handleHealthCheck(response, callback);
        return true;
      } else if ("/execute".equals(request.getHttpURI().getPath())
          && "POST".equals(request.getMethod())) {
        handleExecute(request, response, callback);
        return true;
      }
      return false;
    }
  }

  private static void handleExecute(Request request, Response response, Callback callback) {
    ExecuteRequest executeRequest;
    try (InputStream is = Content.Source.asInputStream(request)) {
      String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
      executeRequest = GSON.fromJson(requestBody, ExecuteRequest.class);
    } catch (IOException e) {
      callback.failed(e);
      return;
    }

    // Tests should not be run in parallel, to ensure orderly input/output
    PrintStream originalOut = System.out;
    PrintStream originalErr = System.err;

    ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    ByteArrayOutputStream errContent = new ByteArrayOutputStream();

    try (PrintStream outPs = new PrintStream(outContent, true, StandardCharsets.UTF_8);
        PrintStream errPs = new PrintStream(errContent, true, StandardCharsets.UTF_8)) {
      if (!debug) {
        System.setOut(outPs);
        System.setErr(errPs);
      }

      List<String> args = new java.util.ArrayList<>();
      args.add("--time");
      args.add(executeRequest.faketime);
      args.addAll(Arrays.asList(executeRequest.args));

      int exitCode = new picocli.CommandLine(new Tuf()).execute(args.toArray(String[]::new));

      Map<String, Object> responseMap =
          Map.of(
              "stdout", outContent.toString(StandardCharsets.UTF_8),
              "stderr", errContent.toString(StandardCharsets.UTF_8),
              "exitCode", exitCode);
      String jsonResponse = GSON.toJson(responseMap);

      response.getHeaders().put(HttpHeader.CONTENT_TYPE, "application/json");
      Content.Sink.write(response, true, jsonResponse, callback);
    } finally {
      if (!debug) {
        System.setOut(originalOut);
        System.setErr(originalErr);
      }
    }
  }

  private static void handleHealthCheck(Response response, Callback callback) throws IOException {
    response.getHeaders().put(HttpHeader.CONTENT_TYPE, "text/plain");
    Content.Sink.write(response, true, "OK", callback);
  }
}
