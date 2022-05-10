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

import com.nimbusds.jose.JOSEException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.sigstore.json.GsonSupplier;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class FakeCTLogServer implements AutoCloseable {

  private final HttpServer server;

  public FakeCTLogServer(HttpServer server) {
    this.server = server;
  }

  public URI getURI() {
    String address = server.getAddress().getHostString();
    int port = server.getAddress().getPort();
    return URI.create("http://" + address + ":" + port);
  }

  public static FakeCTLogServer startNewServer() throws IOException, JOSEException {
    HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    FakeCTLogServer testServer = new FakeCTLogServer(server);
    server.createContext("/", testServer::handleSctRequest);
    server.setExecutor(null); // creates a default executor
    server.start();
    return testServer;
  }

  public void handleSctRequest(HttpExchange t) throws IOException {
    // we dont really care about the input, we're are not testing fulcio, just the api
    Map<String, Object> content = new HashMap<>();
    content.put("sct_version", 0);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      content.put("id", digest.digest("test_id".getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IOException(e);
    }
    // this is a signature stolen from a valid sct, but will not verify
    content.put(
        "signature",
        Base64.getDecoder()
            .decode(
                "BAMARjBEAiBwHMgDtObhrT8wkWid01FXlqvXz1tsRei64siSuwZp7gIgdyRBYHatNaOezI/AW57lKkUffra4cKOGdO+oHKBJARI="));
    content.put("timestamp", System.currentTimeMillis());
    String resp = new GsonSupplier().get().toJson(content);

    t.sendResponseHeaders(200, resp.length());
    OutputStream body = t.getResponseBody();
    body.write(resp.getBytes());
    body.close();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
