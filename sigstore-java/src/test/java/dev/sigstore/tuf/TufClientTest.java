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
package dev.sigstore.tuf;

import static org.junit.jupiter.api.Assertions.*;

import dev.sigstore.json.GsonSupplier;
import dev.sigstore.tuf.model.Root;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.Resource;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class TufClientTest {

  public static final String TEST_STATIC_UPDATE_TIME = "2022-09-09T13:37:00.00Z";
  static Server remote;
  static String remoteUrl;
  @TempDir Path localStore;
  @TempDir static Path localMirror;
  Path tufTestData = Paths.get("src/test/resources/dev/sigstore/tuf/");

  @BeforeAll
  static void startRemoteResourceServer() throws Exception {
    remote = new Server();
    ServerConnector connector = new ServerConnector(remote);
    connector.setHost("127.0.0.1");
    remote.addConnector(connector);
    ResourceHandler handler = new ResourceHandler();
    handler.setBaseResource(Resource.newResource(localMirror.toUri()));
    handler.setDirectoriesListed(true);
    handler.setAcceptRanges(true);
    remote.setHandler(handler);
    remote.start();
    remoteUrl = "http://" + connector.getHost() + ":" + connector.getLocalPort();
    System.out.println("TUF local server listening on: " + remoteUrl);
  }

  @Test
  public void testRootUpdate_fromProdData()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-prod", "1.root.json", "2.root.json", "3.root.json", "4.root.json");
    var client = createTufClient();
    Path trustedRoot = tufTestData.resolve("trusted-root.json");
    client.updateRoot(trustedRoot, new URL(remoteUrl), localStore);
    assertStoreContains("root.json");
    Root oldRoot = loadRoot(trustedRoot);
    Root newRoot = loadRoot(localStore.resolve("root.json"));
    assertRootVersionIncreased(oldRoot, newRoot);
    assertRootNotExpired(newRoot);
  }

  @Test
  public void testRootUpdate_notEnoughSignatures()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-unsigned", "2.root.json");
    var client = createTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (SignatureVerificationException e) {
      assertEquals(3, e.requiredSignatures);
      assertEquals(0, e.verifiedSignatures);
    }
  }

  @Test
  public void testRootUpdate_expiredRoot()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-expired", "2.root.json");
    var client = createTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (RootExpiredException e) {
      assertEquals(ZonedDateTime.parse(TEST_STATIC_UPDATE_TIME), e.getUpdateTime());
      // straight from remote-repo-expired/2.root.json
      assertEquals(
          ZonedDateTime.parse("2022-05-11T19:09:02.663975009Z"), e.getRootExpirationTime());
    }
  }

  @Test
  public void testRootUpdate_inconsistentVersion()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-inconsistent-version", "2.root.json");
    var client = createTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (RoleVersionException e) {
      assertEquals(2, e.getExpectedVersion());
      assertEquals(3, e.getFoundVersion());
    }
  }

  @Test
  public void testRootUpdate_metaFileTooBig()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-meta-file-too-big", "2.root.json");
    var client = createTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (MetaFileExceedsMaxException e) {
    }
  }

  @NotNull
  private static TufClient createTufClient() {
    TufClient client = new TufClient();
    // set a fixed time to ensure test results are reproducible.
    client.clock = Clock.fixed(Instant.parse(TEST_STATIC_UPDATE_TIME), ZoneOffset.UTC);
    return client;
  }

  private void setupMirror(String repoFolder, String... files) throws IOException {
    for (String file : files) {
      Files.copy(tufTestData.resolve(repoFolder).resolve(file), localMirror.resolve(file));
    }
  }

  private void assertRootNotExpired(Root root) {
    assertTrue(
        root.getSignedMeta()
            .getExpiresAsDate()
            .isAfter(ZonedDateTime.parse(TEST_STATIC_UPDATE_TIME)));
  }

  private void assertRootVersionIncreased(Root oldRoot, Root newRoot) throws IOException {
    assertTrue(oldRoot.getSignedMeta().getVersion() <= newRoot.getSignedMeta().getVersion());
  }

  private void assertStoreContains(String resource) {
    assertTrue(localStore.resolve(resource).toFile().exists());
  }

  Root loadRoot(Path rootPath) throws IOException {
    return GsonSupplier.GSON.get().fromJson(Files.readString(rootPath), Root.class);
  }

  @AfterEach
  void clearLocalMirror() {
    for (File file : localMirror.toFile().listFiles()) {
      file.delete();
    }
  }

  @AfterAll
  static void shutdownRemoteResourceServer() throws Exception {
    remote.stop();
  }
}
