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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import dev.sigstore.encryption.signers.Verifier;
import dev.sigstore.encryption.signers.VerifierSupplier;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.json.GsonSupplier;
import dev.sigstore.tuf.model.*;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.tuple.Pair;
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
    var client = createTimeStaticTufClient();
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
    var client = createTimeStaticTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (SignatureVerificationException e) {
      assertEquals(3, e.getRequiredSignatures());
      assertEquals(0, e.getVerifiedSignatures());
    }
  }

  @Test
  public void testRootUpdate_expiredRoot()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("remote-repo-expired", "2.root.json");
    var client = createTimeStaticTufClient();
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
    var client = createTimeStaticTufClient();
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
    var client = createTimeStaticTufClient();
    try {
      client.updateRoot(tufTestData.resolve("trusted-root.json"), new URL(remoteUrl), localStore);
      fail();
    } catch (MetaFileExceedsMaxException e) {
    }
  }

  // sigs and keys with the same number have the same key ids.
  static final Signature SIG_1 =
      ImmutableSignature.builder()
          .keyId("2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97")
          .signature(
              "3046022100f7d4abde3d694fba01af172466629249a6743efd04c3999f958494842a7aee1f022100d19a295f9225247f17650fdb4ad50b99c2326700aadd0afaec4ae418941c7c59")
          .build();
  static final Signature SIG_2 =
      ImmutableSignature.builder()
          .keyId("eaf22372f417dd618a46f6c627dbc276e9fd30a004fc94f9be946e73f8bd090b")
          .signature(
              "3045022075ec28360b3e310db9d3de281a5286e37884aefd9f0b7193ad67c68ab6ee95a2022100aa08a93c58d74d9cb128cea765cae378efe86092f253b75fd427aede48ac7e22")
          .build();
  static final Pair<String, Key> PUB_KEY_1 =
      Pair.of(
          "2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97",
          newKey(
              "04cbc5cab2684160323c25cd06c3307178a6b1d1c9b949328453ae473c5ba7527e35b13f298b41633382241f3fd8526c262d43b45adee5c618fa0642c82b8a9803"));
  static final Pair<String, Key> PUB_KEY_2 =
      Pair.of(
          "eaf22372f417dd618a46f6c627dbc276e9fd30a004fc94f9be946e73f8bd090b",
          newKey(
              "04117b33dd265715bf23315e368faa499728db8d1f0a377070a1c7b1aba2cc21be6ab1628e42f2cdd7a35479f2dce07b303a8ba646c55569a8d2a504ba7e86e447"));
  static final Pair<String, Key> PUB_KEY_3 =
      Pair.of(
          "f40f32044071a9365505da3d1e3be6561f6f22d0e60cf51df783999f6c3429cb",
          newKey(
              "04cc1cd53a61c23e88cc54b488dfae168a257c34fac3e88811c55962b24cffbfecb724447999c54670e365883716302e49da57c79a33cd3e16f81fbc66f0bcdf48"));

  @Test
  public void testVerifyDelegate_verified()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    List<Signature> sigs = ImmutableList.of(SIG_1, SIG_2);

    Map<String, Key> publicKeys =
        ImmutableMap.of(
            PUB_KEY_1.getLeft(), PUB_KEY_1.getRight(),
            PUB_KEY_2.getLeft(), PUB_KEY_2.getRight());
    Role delegate =
        ImmutableRootRole.builder()
            .addKeyids(PUB_KEY_1.getLeft(), PUB_KEY_2.getLeft())
            .threshold(2)
            .build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    createAlwaysVerifyingTufClient()
        .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
    // we are good
  }

  @Test
  public void testVerifyDelegate_belowThreshold()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    List<Signature> sigs = ImmutableList.of(SIG_1, SIG_2);

    Map<String, Key> publicKeys = ImmutableMap.of(PUB_KEY_1.getLeft(), PUB_KEY_1.getRight());
    Role delegate =
        ImmutableRootRole.builder()
            .addKeyids(PUB_KEY_1.getLeft(), PUB_KEY_2.getLeft())
            .threshold(2)
            .build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    try {
      createAlwaysVerifyingTufClient()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      assertEquals(1, e.getVerifiedSignatures());
      assertEquals(2, e.getRequiredSignatures());
    }
  }

  // Just testing boundary conditions for iteration bugs.
  @Test
  public void testVerifyDelegate_emptyLists()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    List<Signature> sigs = ImmutableList.of();

    Map<String, Key> publicKeys = ImmutableMap.of();
    Role delegate = ImmutableRootRole.builder().addKeyids().threshold(2).build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    try {
      createAlwaysVerifyingTufClient()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      assertEquals(0, e.getVerifiedSignatures());
      assertEquals(2, e.getRequiredSignatures());
    }
  }

  @Test
  public void testVerifyDelegate_goodSigsAndKeysButNotInRole()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    List<Signature> sigs = ImmutableList.of(SIG_1, SIG_2);

    Map<String, Key> publicKeys =
        ImmutableMap.of(
            PUB_KEY_1.getLeft(), PUB_KEY_1.getRight(),
            PUB_KEY_2.getLeft(), PUB_KEY_2.getRight());
    Role delegate =
        ImmutableRootRole.builder()
            .addKeyids(PUB_KEY_1.getLeft(), PUB_KEY_3.getLeft())
            .threshold(2)
            .build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    try {
      createAlwaysVerifyingTufClient()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      // pub key #1 and #3 were allowed, but only #1 and #2 were present so verification only
      // verified #1.
      assertEquals(1, e.getVerifiedSignatures());
      assertEquals(2, e.getRequiredSignatures());
    }
  }

  static Key newKey(String keyContents) {
    return ImmutableKey.builder()
        .keyType("ecdsa-sha2-nistp256")
        .addKeyIdHashAlgorithms("sha256", "sha513")
        .scheme("ecdsa-sha2-nistp256")
        .putKeyVal("public", keyContents)
        .build();
  }

  @NotNull
  private static TufClient createTimeStaticTufClient() {
    return new TufClient(
        Clock.fixed(Instant.parse(TEST_STATIC_UPDATE_TIME), ZoneOffset.UTC), Verifiers.INSTANCE);
  }

  @NotNull
  private static TufClient createAlwaysVerifyingTufClient() {
    return new TufClient(
        new VerifierSupplier() {
          @Override
          public Verifier newVerifier(PublicKey publicKey) throws NoSuchAlgorithmException {
            return new Verifier() {
              @Override
              public PublicKey getPublicKey() {
                return null;
              }

              @Override
              public boolean verify(byte[] artifact, byte[] signature)
                  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
                return true;
              }

              @Override
              public boolean verifyDigest(byte[] artifactDigest, byte[] signature)
                  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
                return true;
              }
            };
          }
        });
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
