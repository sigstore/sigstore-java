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

import static dev.sigstore.testkit.tuf.TestResources.UPDATER_REAL_TRUSTED_ROOT;
import static dev.sigstore.testkit.tuf.TestResources.UPDATER_SYNTHETIC_TRUSTED_ROOT;
import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.gson.JsonSyntaxException;
import dev.sigstore.encryption.signers.Verifier;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.testkit.tuf.TestResources;
import dev.sigstore.tuf.model.*;
import dev.sigstore.tuf.model.Root;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SymlinkAllowedResourceAliasChecker;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.Resource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class UpdaterTest {

  public static final String TEST_STATIC_UPDATE_TIME = "2022-09-09T13:37:00.00Z";

  static Server remote;
  static String remoteUrl;
  @TempDir Path localStorePath;
  @TempDir static Path localMirrorPath;

  @BeforeAll
  static void startRemoteResourceServer() throws Exception {
    remote = new Server();
    ServerConnector connector = new ServerConnector(remote);
    connector.setHost("127.0.0.1");
    remote.addConnector(connector);

    ResourceHandler resourceHandler = new ResourceHandler();
    Resource resourceBase = Resource.newResource(localMirrorPath.toAbsolutePath());
    resourceHandler.setBaseResource(resourceBase);
    resourceHandler.setDirectoriesListed(true);
    resourceHandler.setDirAllowed(true);
    resourceHandler.setAcceptRanges(true);
    ContextHandler symlinkAllowingHandler = new ContextHandler();
    symlinkAllowingHandler.setContextPath("/");
    symlinkAllowingHandler.setAllowNullPathInfo(true);
    symlinkAllowingHandler.setHandler(resourceHandler);
    symlinkAllowingHandler.setBaseResource(resourceBase);
    // the @TempDir locations on OS X are under /var/.. which is a symlink to /private/var and are
    // not followed by default in Jetty for security reasons.
    symlinkAllowingHandler.clearAliasChecks();
    symlinkAllowingHandler.addAliasCheck(
        new SymlinkAllowedResourceAliasChecker(symlinkAllowingHandler));
    remote.setHandler(symlinkAllowingHandler);
    remote.start();
    remoteUrl = "http://" + connector.getHost() + ":" + connector.getLocalPort();
    System.out.println("TUF local server listening on: " + remoteUrl);
  }

  @Test
  public void testRootUpdate_fromProdData()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "real/prod", "1.root.json", "2.root.json", "3.root.json", "4.root.json", "5.root.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_REAL_TRUSTED_ROOT);
    updater.updateRoot();
    assertStoreContains("root.json");
    Root oldRoot = TestResources.loadRoot(UPDATER_REAL_TRUSTED_ROOT);
    Root newRoot = TestResources.loadRoot(localStorePath.resolve("root.json"));
    assertRootVersionIncreased(oldRoot, newRoot);
    assertRootNotExpired(newRoot);
  }

  @Test
  public void testRootUpdate_notEnoughSignatures()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/root-unsigned", "2.root.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    try {
      updater.updateRoot();
      fail(
          "SignastureVerificationException was expected as 0 verification signatures should be present.");
    } catch (SignatureVerificationException e) {
      assertEquals(1, e.getRequiredSignatures(), "expected signature threshold");
      assertEquals(0, e.getVerifiedSignatures(), "expected verified signatures");
    }
  }

  @Test
  public void testRootUpdate_expiredRoot()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json");
    // root expires 2023-03-09T18:02:21Z
    var updater =
        createTimeStaticUpdater(
            localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT, "2023-05-13T14:35:59Z");
    try {
      updater.updateRoot();
      fail("The remote repo should be expired and cause a RoleExpiredException.");
    } catch (RoleExpiredException e) {
      assertEquals(ZonedDateTime.parse("2023-05-13T14:35:59Z"), e.getUpdateTime());
      // straight from remote-repo-expired/2.root.json
      assertEquals(ZonedDateTime.parse("2023-05-13T14:35:58Z"), e.getRoleExpirationTime());
    }
  }

  @Test
  public void testRootUpdate_wrongVersion()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          SignatureVerificationException {
    setupMirror("synthetic/root-wrong-version", "2.root.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    try {
      updater.updateRoot();
      fail("RoleVersionException expected fetching 2.root.json with a version field set to 3.");
    } catch (RollbackVersionException e) {
      assertEquals(2, e.getCurrentVersion(), "expected root version");
      assertEquals(1, e.getFoundVersion(), "found version");
    }
  }

  @Test
  public void testRootUpdate_metaFileTooBig()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/root-too-big", "2.root.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    try {
      updater.updateRoot();
      fail("MetaFileExceedsMaxException expected as 2.root.json is larger than max allowable.");
    } catch (FileExceedsMaxLengthException e) {
      // expected
    }
  }

  @Test
  public void testTimestampUpdate_throwMetaNotFoundException() throws IOException {
    setupMirror("synthetic/test-template", "2.root.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    assertThrows(
        FileNotFoundException.class,
        () -> {
          updater.updateTimestamp(updater.updateRoot());
        });
  }

  @Test
  public void testTimestampUpdate_throwsSignatureVerificationException()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/timestamp-unsigned", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    try {
      updater.updateTimestamp(updater.updateRoot());
      fail("The timestamp was not signed so should have thown a SignatureVerificationException.");
    } catch (SignatureVerificationException e) {
      assertEquals(0, e.getVerifiedSignatures(), "verified signature threshold did not match");
      assertEquals(1, e.getRequiredSignatures(), "required signatures found did not match");
    }
  }

  @Test
  public void testTimestampUpdate_throwsRollbackVersionException()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    bootstrapLocalStore(localStorePath, "synthetic/test-template", "root.json", "timestamp.json");
    setupMirror("synthetic/timestamp-rollback-version", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    try {
      updater.updateTimestamp(updater.updateRoot());
      fail(
          "The repo in this test provides an older signed timestamp version that should have caused a RoleVersionException.");
    } catch (RollbackVersionException e) {
      assertEquals(3, e.getCurrentVersion(), "expected timestamp version did not match");
      assertEquals(1, e.getFoundVersion(), "found timestamp version did not match");
    }
  }

  @Test
  public void testTimestampUpdate_noUpdate()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    bootstrapLocalStore(localStorePath, "synthetic/test-template", "2.root.json", "timestamp.json");
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    assertTrue(
        updater.updateTimestamp(updater.updateRoot()).isEmpty(),
        "We expect the updater to return an empty timestamp if there are no updates");
  }

  @Test
  public void testTimestampUpdate_throwsRoleExpiredException()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json");
    // timestamp expires 2022-12-10T18:07:30Z
    var updater =
        createTimeStaticUpdater(
            localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT, "2023-02-13T15:37:49Z");
    try {
      updater.updateTimestamp(updater.updateRoot());
      fail("Expects a RoleExpiredException as the repo timestamp.json should be expired.");
    } catch (RoleExpiredException e) {
      // expected.
    }
  }

  @Test
  public void testTimestampUpdate_noPreviousTimestamp_success()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    updater.updateTimestamp(updater.updateRoot());
    assertStoreContains("timestamp.json");
    assertEquals(
        3,
        updater.getLocalStore().loadTimestamp().get().getSignedMeta().getVersion(),
        "timestamp version did not match expectations");
  }

  @Test
  public void testTimestampUpdate_updateExistingTimestamp_success()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    bootstrapLocalStore(
        localStorePath, "synthetic/test-template", "1.root.json", "1.timestamp.json");
    setupMirror("synthetic/test-template", "1.root.json", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    assertEquals(
        1,
        updater.getLocalStore().loadTimestamp().get().getSignedMeta().getVersion(),
        "timestamp version should start at 1 before the update.");
    updater.updateTimestamp(updater.updateRoot());
    assertStoreContains("timestamp.json");
    assertEquals(
        3,
        updater.getLocalStore().loadTimestamp().get().getSignedMeta().getVersion(),
        "timestamp version did not match expectations.");
  }

  @Test
  public void testSnapshotUpdate_snapshotMetaMissing()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    assertThrows(
        FileNotFoundException.class,
        () -> updater.updateSnapshot(root, timestamp.get()),
        "Expected remote with no snapshot.json to throw FileNotFoundException.");
  }

  @Test
  public void testSnapshotUpdate_invalidHash()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/snapshot-invalid-hash", "2.root.json", "timestamp.json", "3.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    assertThrows(
        InvalidHashesException.class,
        () -> {
          updater.updateSnapshot(root, timestamp.get());
        },
        "snapshot.json edited and should fail hash test.");
  }

  @Test
  public void testSnapshotUpdate_timestampSnapshotVersionMismatch()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/snapshot-version-mismatch", "2.root.json", "timestamp.json", "3.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    assertThrows(
        SnapshotVersionMismatchException.class,
        () -> {
          updater.updateSnapshot(root, timestamp.get());
        },
        "snapshot version should not match the timestamp metadata.");
  }

  @Test
  public void testSnapshotUpdate_snapshotTargetMissing()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    bootstrapLocalStore(
        localStorePath,
        "synthetic/test-template",
        "2.root.json",
        "1.timestamp.json",
        "1.snapshot.json");
    setupMirror(
        "synthetic/snapshot-target-missing", "2.root.json", "timestamp.json", "4.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    assertThrows(
        SnapshotTargetMissingException.class,
        () -> {
          updater.updateSnapshot(root, timestamp.get());
        },
        "All targets from previous versions of snapshot should be contained in future versions of snapshot.");
  }

  @Test
  public void testSnapshotUpdate_snapshotTargetVersionRollback()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    bootstrapLocalStore(
        localStorePath,
        "synthetic/test-template",
        "2.root.json",
        "2.timestamp.json",
        "2.snapshot.json");
    setupMirror(
        "synthetic/snapshot-target-version-rollback",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    assertThrows(
        SnapshotTargetVersionException.class,
        () -> {
          updater.updateSnapshot(root, timestamp.get());
        },
        "The new snapshot.json has a targets.json version that is lower than the current target and so we expect a SnapshotTargetVersionException.");
  }

  @Test
  public void testSnapshotUpdate_success()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json", "3.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    Root root = updater.updateRoot();
    Timestamp timestamp = updater.updateTimestamp(root).get();
    Snapshot result = updater.updateSnapshot(root, timestamp);
    assertNotNull(result);
  }

  @Test
  public void testSnapshotUpdate_expired()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/snapshot-expired", "2.root.json", "timestamp.json", "3.snapshot.json");
    // snapshot expires 2022-11-19T18:07:27Z
    var updater =
        createTimeStaticUpdater(
            localStorePath,
            UPDATER_SYNTHETIC_TRUSTED_ROOT,
            "2022-11-20T18:07:27Z"); // one day after
    Root root = updater.updateRoot();
    Timestamp timestamp = updater.updateTimestamp(root).get();
    try {
      updater.updateSnapshot(root, timestamp);
      fail("Expects a RoleExpiredException as the repo snapshot.json should be expired.");
    } catch (RoleExpiredException e) {
      // pass
    }
  }

  @Test
  public void testTargetsUpdate_targetMetaMissing()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror("synthetic/test-template", "2.root.json", "timestamp.json", "3.snapshot.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    assertThrows(
        FileNotFoundException.class,
        () -> updater.updateTargets(root, snapshot),
        "Expected remote with no target.json to throw FileNotFoundException.");
  }

  @Test
  public void testTargetsUpdate_invalidHash()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/targets-invalid-hash",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    assertThrows(
        InvalidHashesException.class,
        () -> updater.updateTargets(root, snapshot),
        "targets.json has been modified to have an invalid hash.");
  }

  @Test
  public void testTargetsUpdate_snapshotVersionMismatch()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/targets-snapshot-version-mismatch",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    assertThrows(
        SnapshotVersionMismatchException.class,
        () -> updater.updateTargets(root, snapshot),
        "targets version should not match the snapshot targets metadata.");
  }

  @Test
  public void testTargetsUpdate_targetExpired()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    // targets expires 2022-11-19T18:07:27Z
    setupMirror(
        "synthetic/targets-expired",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater =
        createTimeStaticUpdater(
            localStorePath,
            UPDATER_SYNTHETIC_TRUSTED_ROOT,
            "2022-11-20T18:07:27Z"); // one day after
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    assertThrows(
        RoleExpiredException.class,
        () -> updater.updateTargets(root, snapshot),
        "targets are out of date and should cause RoleExpiredException.");
  }

  @Test
  public void testTargetsUpdate_success()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/test-template",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater =
        createTimeStaticUpdater(
            localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT, "2022-11-20T18:07:27Z");
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    var targets = updater.updateTargets(root, snapshot);
    assertNotNull(targets);
    assertNotNull(updater.getLocalStore().loadTargets());
    assertEquals(
        targets.getSignedMeta(), updater.getLocalStore().loadTargets().get().getSignedMeta());
  }

  @Test
  public void testTargetsDownload_targetMissingTargetMetadata()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/targets-download-missing-target-metadata",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    assertThrows(
        JsonSyntaxException.class,
        () -> updater.updateTargets(root, snapshot),
        "targets.json data should be causing a gson error due to missing TargetData. If at some point we support nullable TargetData this test should be updated to expect TargetMetadataMissingException while calling downloadTargets().");
  }

  @Test
  public void testTargetsDownload_targetFileNotFound()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/test-template",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    var targets = updater.updateTargets(root, snapshot);
    assertThrows(
        FileNotFoundException.class,
        () -> updater.downloadTargets(targets),
        "the target file for download should be missing from the repo and cause an exception.");
  }

  @Test
  public void testTargetsDownload_targetInvalidLength()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/targets-download-invalid-length",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json",
        "targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    var targets = updater.updateTargets(root, snapshot);
    assertThrows(
        FileExceedsMaxLengthException.class,
        () -> updater.downloadTargets(targets),
        "The target file is expected to not match the length specified in targets.json target data.");
  }

  @Test
  public void testTargetsDownload_targetFileInvalidHash()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/targets-download-invalid-hash",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json",
        "targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    var targets = updater.updateTargets(root, snapshot);
    assertThrows(
        InvalidHashesException.class,
        () -> updater.downloadTargets(targets),
        "The target file has been modified and should not match the expected hash");
  }

  @Test
  public void testTargetsDownload_success()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setupMirror(
        "synthetic/test-template",
        "2.root.json",
        "timestamp.json",
        "3.snapshot.json",
        "3.targets.json",
        "targets/860de8f9a858eea7190fcfa1b53fe55914d3c38f17f8f542273012d19cc9509bb423f37b7c13c577a56339ad7f45273b479b1d0df837cb6e20a550c27cce0885.test.txt",
        "targets/32005f02eac21b4cf161a02495330b6c14b548622b5f7e19d59ecfa622de650603ecceea39ed86cc322749a813503a72ad14ce5462c822b511eaf2f2cd2ad8f2.test.txt.v2",
        "targets/53904bc6216230bf8da0ec42d34004a3f36764de698638641870e37d270e4fd13e1079285f8bca73c2857a279f6f7fbc82038274c3eb48ec5bb2da9b2e30491a.test2.txt");
    var updater = createTimeStaticUpdater(localStorePath, UPDATER_SYNTHETIC_TRUSTED_ROOT);
    var root = updater.updateRoot();
    var timestamp = updater.updateTimestamp(root);
    var snapshot = updater.updateSnapshot(root, timestamp.get());
    var targets = updater.updateTargets(root, snapshot);
    updater.downloadTargets(targets);
    assertTrue(updater.getLocalStore().getTargetFile("test.txt") != null);
    assertTrue(updater.getLocalStore().getTargetFile("test.txt.v2") != null);
    assertTrue(updater.getLocalStore().getTargetFile("test2.txt") != null);
  }

  private static final byte[] TEST_HASH_VERIFYIER_BYTES =
      "testdata".getBytes(StandardCharsets.UTF_8);
  private static final String GOOD_256_HASH =
      "810ff2fb242a5dee4220f2cb0e6a519891fb67f2f828a6cab4ef8894633b1f50";
  private static final String GOOD_512_HASH =
      "76f4ca48f5eea90471fc0579e2fb21078e06641a7233395825550e5629efca7f06dd30bcd387ddf2fbc114beeab3f0dd995eb5743751bd7273d0e514ecb3939b";

  private static final String BAD_HASH = "bad";

  private static class TestHashes implements Hashes {

    private final String sha256;
    private final String sha512;

    private TestHashes(String sha256, String sha512) {
      this.sha256 = sha256;
      this.sha512 = sha512;
    }

    @Nullable
    @Override
    public String getSha256() {
      return sha256;
    }

    @Nullable
    @Override
    public String getSha512() {
      return sha512;
    }
  }

  @Test
  public void testVerifyHashes_noHashes() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Updater.verifyHashes("test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(null, null)),
        "If no hashes are provided it should cause an error.");
  }

  @Test
  public void testVerifyHashes_bad256Null512() {
    assertThrows(
        InvalidHashesException.class,
        () ->
            Updater.verifyHashes("test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(BAD_HASH, null)),
        "If the hash doesn't match we expect an error.");
  }

  @Test
  public void testVerifyHashes_bad512Null256() {
    assertThrows(
        InvalidHashesException.class,
        () ->
            Updater.verifyHashes("test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(null, BAD_HASH)),
        "If the hash doesn't match we expect an error.");
  }

  @Test
  public void testVerifyHashes_badBoth() {
    assertThrows(
        InvalidHashesException.class,
        () ->
            Updater.verifyHashes(
                "test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(BAD_HASH, BAD_HASH)),
        "If both hashes don't match we still expect an error.");
  }

  @Test
  public void testVerifyHashes_good256Null512() {
    // We don't expect an exception since we'e provided a valid hash 256 value.
    Updater.verifyHashes("test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(GOOD_256_HASH, null));
  }

  @Test
  public void testVerifyHashes_good512Null256() {
    // We don't expect an exception since we'e provided a valid hash 512 value.
    Updater.verifyHashes("test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(null, GOOD_512_HASH));
  }

  @Test
  public void testVerifyHashes_goodBoth() {
    // We don't expect an exception since we'e provided a valid hash 512 value.
    Updater.verifyHashes(
        "test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(GOOD_256_HASH, GOOD_512_HASH));
  }

  @Test
  public void testVerifyHashes_good256Bad512() {
    assertThrows(
        InvalidHashesException.class,
        () ->
            Updater.verifyHashes(
                "test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(GOOD_256_HASH, BAD_HASH)),
        "If one of the hashes is invalid we still produce an error.");
  }

  @Test
  public void testVerifyHashes_good512Bad256() {
    assertThrows(
        InvalidHashesException.class,
        () ->
            Updater.verifyHashes(
                "test", TEST_HASH_VERIFYIER_BYTES, new TestHashes(BAD_HASH, GOOD_512_HASH)),
        "If one of the hashes is invalid we still expect an error.");
  }

  private void bootstrapLocalStore(
      Path localStore, String tufFolder, String rootFile, String... roleFiles) throws IOException {
    Files.copy(
        TestResources.TUF_TEST_DATA_DIRECTORY.resolve(tufFolder).resolve(rootFile),
        localStore.resolve("root.json"));
    for (String file : roleFiles) {
      // strip version from versioned filenames (e.g. 1.timestamp.json)
      String destinationFilename =
          file.matches("^\\d.*") ? file.substring(file.indexOf('.') + 1) : file;
      Files.copy(
          TestResources.TUF_TEST_DATA_DIRECTORY.resolve(tufFolder).resolve(file),
          localStore.resolve(destinationFilename));
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
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
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

    createAlwaysVerifyingUpdater().verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
    // we are good
  }

  @Test
  public void testVerifyDelegate_verificationFailed()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
    List<Signature> sigs = ImmutableList.of(SIG_1, SIG_2);

    Map<String, Key> publicKeys = ImmutableMap.of(PUB_KEY_1.getLeft(), PUB_KEY_1.getRight());
    Role delegate = ImmutableRootRole.builder().addKeyids(PUB_KEY_1.getLeft()).threshold(1).build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);
    var updater = Updater.builder().setVerifiers(ALWAYS_FAILS).build();
    try {
      updater.verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail("This should have failed since the public key for PUB_KEY_1 should fail to verify.");
    } catch (SignatureVerificationException e) {
      assertEquals(
          1, e.getRequiredSignatures(), "required signature count did not match expectations.");
      assertEquals(0, e.getVerifiedSignatures(), "verified signature expectations did not match.");
    }
  }

  @Test
  public void testVerifyDelegate_belowThreshold()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
    List<Signature> sigs = ImmutableList.of(SIG_1, SIG_2);

    Map<String, Key> publicKeys = ImmutableMap.of(PUB_KEY_1.getLeft(), PUB_KEY_1.getRight());
    Role delegate =
        ImmutableRootRole.builder()
            .addKeyids(PUB_KEY_1.getLeft(), PUB_KEY_2.getLeft())
            .threshold(2)
            .build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    try {
      createAlwaysVerifyingUpdater()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      assertEquals(1, e.getVerifiedSignatures(), "verified signature expectations did not match.");
      assertEquals(
          2, e.getRequiredSignatures(), "required signature count did not match expectations.");
    }
  }

  // Just testing boundary conditions for iteration bugs.
  @Test
  public void testVerifyDelegate_emptyLists()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
    List<Signature> sigs = ImmutableList.of();

    Map<String, Key> publicKeys = ImmutableMap.of();
    Role delegate = ImmutableRootRole.builder().addKeyids().threshold(2).build();
    byte[] verificationMaterial = "alksdjfas".getBytes(StandardCharsets.UTF_8);

    try {
      createAlwaysVerifyingUpdater()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      assertEquals(0, e.getVerifiedSignatures(), "verified signature expectations did not match.");
      assertEquals(
          2, e.getRequiredSignatures(), "required signature count did not match expectations.");
    }
  }

  @Test
  public void testVerifyDelegate_goodSigsAndKeysButNotInRole()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
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
      createAlwaysVerifyingUpdater()
          .verifyDelegate(sigs, publicKeys, delegate, verificationMaterial);
      fail(
          "Test should have thrown SignatureVerificationException due to insufficient public keys");
    } catch (SignatureVerificationException e) {
      // pub key #1 and #3 were allowed, but only #1 and #2 were present so verification only
      // verified #1.
      assertEquals(1, e.getVerifiedSignatures(), "verified signature expectations did not match.");
      assertEquals(
          2, e.getRequiredSignatures(), "required signature count did not match expectations.");
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
  private static Updater createTimeStaticUpdater(Path localStore, Path trustedRootFile)
      throws IOException {
    return createTimeStaticUpdater(localStore, trustedRootFile, TEST_STATIC_UPDATE_TIME);
  }

  @NotNull
  private static Updater createTimeStaticUpdater(Path localStore, Path trustedRootFile, String time)
      throws IOException {
    return Updater.builder()
        .setClock(Clock.fixed(Instant.parse(time), ZoneOffset.UTC))
        .setVerifiers(Verifiers::newVerifier)
        .setFetcher(HttpMetaFetcher.newFetcher(new URL(remoteUrl)))
        .setTrustedRootPath(trustedRootFile)
        .setLocalStore(FileSystemTufStore.newFileSystemStore(localStore))
        .build();
  }

  @NotNull
  private static Updater createAlwaysVerifyingUpdater() {
    return Updater.builder().setVerifiers(ALWAYS_VERIFIES).build();
  }

  /**
   * Setup a test mirror.
   *
   * @param repoName the directory under test/resources/dev/sigstore/tuf where the test data
   *     resides.
   * @param files files from the test data set to copy into the mirror
   */
  private static void setupMirror(String repoName, String... files) throws IOException {
    TestResources.setupRepoFiles(repoName, localMirrorPath, files);
  }

  private void assertRootNotExpired(Root root) {
    assertTrue(
        root.getSignedMeta()
            .getExpiresAsDate()
            .isAfter(ZonedDateTime.parse(TEST_STATIC_UPDATE_TIME)),
        "The root should not be expired passed test static update time: "
            + TEST_STATIC_UPDATE_TIME);
  }

  private void assertRootVersionIncreased(Root oldRoot, Root newRoot) throws IOException {
    assertTrue(
        oldRoot.getSignedMeta().getVersion() <= newRoot.getSignedMeta().getVersion(),
        "The new root version should be higher than the old root.");
  }

  private void assertStoreContains(String resource) {
    assertTrue(
        localStorePath.resolve(resource).toFile().exists(),
        "The local store was expected to contain: " + resource);
  }

  @AfterEach
  void clearLocalMirror() throws IOException {
    for (File file : localMirrorPath.toFile().listFiles()) {
      FileUtils.forceDelete(file);
    }
  }

  @AfterAll
  static void shutdownRemoteResourceServer() throws Exception {
    remote.stop();
  }

  public static final Verifiers.Supplier ALWAYS_VERIFIES =
      publicKey ->
          new Verifier() {
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
  public static final Verifiers.Supplier ALWAYS_FAILS =
      publicKey ->
          new Verifier() {
            @Override
            public PublicKey getPublicKey() {
              return null;
            }

            @Override
            public boolean verify(byte[] artifact, byte[] signature)
                throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
              return false;
            }

            @Override
            public boolean verifyDigest(byte[] artifactDigest, byte[] signature)
                throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
              return false;
            }
          };
}
