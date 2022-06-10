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

import static dev.sigstore.json.GsonSupplier.GSON;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A fake CT long instance to run per test. Will inject CTLOGURL into the test store so it can be
 * picked up by a Fulcio fixture during initialization.
 */
public class FakeCTLogServer implements BeforeEachCallback, AfterEachCallback {

  // private HttpServer server;
  private MockWebServer server;

  public String getURL() {
    String address = server.getHostName();
    int port = server.getPort();
    return "http://" + address + ":" + port;
  }

  public MockResponse handleSctRequest() {
    // we dont really care about the input, we're are not testing fulcio, just the api
    Map<String, Object> content = new HashMap<>();
    content.put("sct_version", 0);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      content.put("id", digest.digest("test_id".getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    // this is a signature stolen from a valid sct, but will not verify
    content.put(
        "signature",
        Base64.getDecoder()
            .decode(
                "BAMARjBEAiBwHMgDtObhrT8wkWid01FXlqvXz1tsRei64siSuwZp7gIgdyRBYHatNaOezI/AW57lKkUffra4cKOGdO+oHKBJARI="));
    content.put("timestamp", System.currentTimeMillis());
    String resp = GSON.get().toJson(content);

    return new MockResponse().setResponseCode(200).setBody(resp);
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    server = new MockWebServer();
    server.setDispatcher(
        new Dispatcher() {
          @NotNull
          @Override
          public MockResponse dispatch(@NotNull RecordedRequest recordedRequest)
              throws InterruptedException {
            switch (recordedRequest.getPath()) {
              case "/ct/v1/add-chain":
                return handleSctRequest();
            }
            return new MockResponse().setResponseCode(404);
          }
        });
    server.start();
    var ns = ExtensionContext.Namespace.create(context.getTestMethod().orElseThrow().toString());
    context.getStore(ns).put("CTLOGURL", getURL());
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    server.shutdown();
  }
}
