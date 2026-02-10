/*
 * Copyright 2024 The Sigstore Authors.
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

import static dev.sigstore.json.GsonSupplier.GSON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.Resources;
import dev.sigstore.tuf.model.Snapshot;
import dev.sigstore.tuf.model.Targets;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class DelegationTest {

  @TempDir Path tempDir;
  @Mock MetaFetcher metaFetcher;
  @Mock Fetcher targetFetcher;
  @Mock RootProvider rootProvider;
  @Mock TargetStore targetStore;

  private TrustedMetaStore trustedMetaStore;
  private Updater updater;

  @BeforeEach
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    var fsTufStore = FileSystemTufStore.newFileSystemStore(tempDir);
    trustedMetaStore =
        TrustedMetaStore.newTrustedMetaStore(
            PassthroughCacheMetaStore.newPassthroughMetaCache(fsTufStore));

    updater =
        Updater.builder()
            .setClock(Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC))
            .setMetaFetcher(metaFetcher)
            .setTargetFetcher(targetFetcher)
            .setTrustedRootPath(rootProvider)
            .setTrustedMetaStore(trustedMetaStore)
            .setTargetStore(targetStore)
            .build();
  }

  @Test
  public void testMatches() {
    assertTrue(Updater.matches("foo.txt", "foo.txt"));
    assertTrue(Updater.matches("foo.txt", "*.txt"));
    assertTrue(Updater.matches("dir/foo.txt", "dir/*.txt"));
    assertFalse(Updater.matches("dir/foo.txt", "*.txt")); // TUF globs don't match across separators
    assertTrue(Updater.matches("foo-1.txt", "foo-?.txt"));
    assertFalse(Updater.matches("foo-11.txt", "foo-?.txt"));
    assertTrue(Updater.matches("targets/foo.tgz", "targets/*.tgz"));
    assertFalse(Updater.matches("targets/foo.txt", "targets/*.tgz"));
  }

  @Test
  public void testDelegationResolution() throws Exception {
    // 1. Load top-level targets with delegations
    String targetsJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/tuf/model/targets.json"), Charset.defaultCharset());
    Targets targets = GSON.get().fromJson(targetsJson, Targets.class);
    trustedMetaStore.setTargets(targets);

    // 2. Mock rekor.json metadata fetch
    byte[] targetContent = "content".getBytes(Charset.defaultCharset());
    String rekorTargetsJson =
        "{"
            + "  \"signatures\": [{\"keyid\": \"ae0c689c6347ada7359df48934991f4e013193d6ddf3482a5ffb293f74f3b217\", \"sig\": \"deadbeef\"}],"
            + "  \"signed\": {"
            + "    \"_type\": \"targets\","
            + "    \"expires\": \"2030-01-01T00:00:00Z\","
            + "    \"spec_version\": \"1.0\","
            + "    \"targets\": {"
            + "      \"rekor.manual.pub\": {"
            + "        \"hashes\": {\"sha256\": \"ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73\"},"
            + "        \"length\": "
            + targetContent.length
            + "      }"
            + "    },"
            + "    \"version\": 3"
            + "  }"
            + "}";
    Targets rekorTargets = GSON.get().fromJson(rekorTargetsJson, Targets.class);
    byte[] rekorBytes = rekorTargetsJson.getBytes(Charset.defaultCharset());

    // 3. Mock snapshot to include rekor.json with correct hashes for our mock string
    String snapshotJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/tuf/model/snapshot.json"),
            Charset.defaultCharset());
    snapshotJson =
        snapshotJson.replace(
            "9d2e1a5842937d8e0d3e3759170b0ad15c56c5df36afc5cf73583ddd283a463b",
            com.google.common.hash.Hashing.sha256().hashBytes(rekorBytes).toString());
    snapshotJson =
        snapshotJson.replace(
            "176e9e710ddddd1b357a7d7970831bae59763395a0c18976110cbd35b25e5412dc50f356ec421a7a30265670cf7aec9ed84ee944ba700ec2394b9c876645b960",
            com.google.common.hash.Hashing.sha512().hashBytes(rekorBytes).toString());
    snapshotJson = snapshotJson.replace("797", Integer.toString(rekorBytes.length));
    Snapshot snapshot = GSON.get().fromJson(snapshotJson, Snapshot.class);
    trustedMetaStore.setSnapshot(snapshot);

    when(metaFetcher.getMeta(eq("rekor"), anyInt(), eq(Targets.class), any()))
        .thenReturn(Optional.of(new MetaFetchResult<>(rekorBytes, rekorTargets)));

    // 4. Try to resolve "rekor.manual.pub"
    // Since we're using Mockito, and Updater.verifyDelegate uses real Verifiers.Supplier,
    // we should use a "always verifiers" supplier if we want to avoid complex key setup.
    updater =
        Updater.builder()
            .setClock(Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC))
            .setVerifiers(key -> (digest, signature) -> true) // Always verify for test
            .setMetaFetcher(metaFetcher)
            .setTargetFetcher(targetFetcher)
            .setTrustedRootPath(rootProvider)
            .setTrustedMetaStore(trustedMetaStore)
            .setTargetStore(targetStore)
            .build();

    // Initialize updateStartTime by calling updateRoot
    when(rootProvider.get())
        .thenReturn(
            Resources.toString(
                Resources.getResource("dev/sigstore/tuf/model/root.json"),
                Charset.defaultCharset()));
    when(metaFetcher.getRootAtVersion(anyInt())).thenReturn(Optional.empty());
    updater.updateRoot();

    // Mock target fetch
    when(targetFetcher.fetchResource(any(), anyInt())).thenReturn(targetContent);

    updater.downloadTarget("rekor.manual.pub");

    // If no exception, it found the target data and tried to download it.
    // We can verify that it correctly resolved the target data.
  }

  /**
   * Tests that a terminating delegation stops the search. The test data has: - rekor:
   * paths=["rekor.*.pub"], terminating=true - staging: paths=["*"], terminating=false
   *
   * <p>Searching for "rekor.unknown.pub" should match the rekor delegation's path pattern, but
   * since the rekor targets don't contain it and rekor is terminating, the search should stop
   * without checking staging.
   */
  @Test
  public void testTerminatingDelegationStopsSearch() throws Exception {
    Updater alwaysVerifyUpdater = initUpdaterWithDelegations();

    // Mock rekor delegation to return targets that do NOT contain "rekor.unknown.pub"
    String rekorTargetsJson =
        "{"
            + "  \"signatures\": [{\"keyid\": \"ae0c689c6347ada7359df48934991f4e013193d6ddf3482a5ffb293f74f3b217\", \"sig\": \"deadbeef\"}],"
            + "  \"signed\": {"
            + "    \"_type\": \"targets\","
            + "    \"expires\": \"2030-01-01T00:00:00Z\","
            + "    \"spec_version\": \"1.0\","
            + "    \"targets\": {},"
            + "    \"version\": 3"
            + "  }"
            + "}";
    Targets rekorTargets = GSON.get().fromJson(rekorTargetsJson, Targets.class);
    byte[] rekorBytes = rekorTargetsJson.getBytes(StandardCharsets.UTF_8);
    mockSnapshotForRole("rekor", rekorBytes, 3);

    when(metaFetcher.getMeta(eq("rekor"), anyInt(), eq(Targets.class), any()))
        .thenReturn(Optional.of(new MetaFetchResult<>(rekorBytes, rekorTargets)));

    // Even though staging would match "rekor.unknown.pub" via "*", the rekor delegation is
    // terminating so the search should stop after rekor.
    assertThrows(
        TargetMetadataMissingException.class,
        () -> alwaysVerifyUpdater.downloadTarget("rekor.unknown.pub"));

    // Verify staging was never fetched
    verify(metaFetcher, never()).getMeta(eq("staging"), anyInt(), eq(Targets.class), any());
  }

  /**
   * Tests that a non-terminating delegation allows the search to continue. Searching for
   * "other.txt" doesn't match rekor's paths ("rekor.*.pub") but does match staging's ("*"). If
   * staging doesn't have it either, the search continues to revocation.
   */
  @Test
  public void testNonTerminatingDelegationContinuesSearch() throws Exception {
    Updater alwaysVerifyUpdater = initUpdaterWithDelegations();

    // Mock staging delegation (non-terminating) - doesn't have "other.txt"
    String stagingTargetsJson =
        "{"
            + "  \"signatures\": [{\"keyid\": \"b811bd53f2d7adcf5d93e6bb4a8ed2e0ca0f83d454a3e51f105c8e8376bc80d4\", \"sig\": \"deadbeef\"}],"
            + "  \"signed\": {"
            + "    \"_type\": \"targets\","
            + "    \"expires\": \"2030-01-01T00:00:00Z\","
            + "    \"spec_version\": \"1.0\","
            + "    \"targets\": {},"
            + "    \"version\": 2"
            + "  }"
            + "}";
    Targets stagingTargets = GSON.get().fromJson(stagingTargetsJson, Targets.class);
    byte[] stagingBytes = stagingTargetsJson.getBytes(StandardCharsets.UTF_8);
    mockSnapshotForRole("staging", stagingBytes, 2);

    when(metaFetcher.getMeta(eq("staging"), anyInt(), eq(Targets.class), any()))
        .thenReturn(Optional.of(new MetaFetchResult<>(stagingBytes, stagingTargets)));

    // Mock revocation delegation (also non-terminating) - has "other.txt"
    byte[] targetContent = "other content".getBytes(StandardCharsets.UTF_8);
    String revocationTargetsJson =
        "{"
            + "  \"signatures\": [{\"keyid\": \"9e7d813e8e16062e60a4540346aa8e7c7782afb7098af0b944ea80a4033a176f\", \"sig\": \"deadbeef\"}],"
            + "  \"signed\": {"
            + "    \"_type\": \"targets\","
            + "    \"expires\": \"2030-01-01T00:00:00Z\","
            + "    \"spec_version\": \"1.0\","
            + "    \"targets\": {"
            + "      \"other.txt\": {"
            + "        \"hashes\": {\"sha256\": \"923b805711041e23a99f07e146591c500261d1c289f62a9d39f8581ceb8a10ca\"},"
            + "        \"length\": "
            + targetContent.length
            + "      }"
            + "    },"
            + "    \"version\": 1"
            + "  }"
            + "}";
    Targets revocationTargets = GSON.get().fromJson(revocationTargetsJson, Targets.class);
    byte[] revocationBytes = revocationTargetsJson.getBytes(StandardCharsets.UTF_8);
    mockSnapshotForRole("revocation", revocationBytes, 1);

    when(metaFetcher.getMeta(eq("revocation"), anyInt(), eq(Targets.class), any()))
        .thenReturn(Optional.of(new MetaFetchResult<>(revocationBytes, revocationTargets)));
    when(targetFetcher.fetchResource(any(), anyInt())).thenReturn(targetContent);

    // "other.txt" doesn't match rekor's "rekor.*.pub", matches staging's "*" (not found there),
    // staging is non-terminating so continues to revocation's "*" where it IS found.
    alwaysVerifyUpdater.downloadTarget("other.txt");

    // Verify that both staging and revocation were fetched (search continued past staging)
    verify(metaFetcher).getMeta(eq("staging"), anyInt(), eq(Targets.class), any());
    verify(metaFetcher).getMeta(eq("revocation"), anyInt(), eq(Targets.class), any());
  }

  /**
   * Helper to set up an always-verifying updater with top-level targets, snapshot, and root
   * initialized.
   */
  private Updater initUpdaterWithDelegations() throws Exception {
    // Load top-level targets with delegations
    String targetsJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/tuf/model/targets.json"), Charset.defaultCharset());
    Targets targets = GSON.get().fromJson(targetsJson, Targets.class);
    trustedMetaStore.setTargets(targets);

    // Load base snapshot (will be modified per-role in mockSnapshotForRole)
    String snapshotJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/tuf/model/snapshot.json"),
            Charset.defaultCharset());
    Snapshot snapshot = GSON.get().fromJson(snapshotJson, Snapshot.class);
    trustedMetaStore.setSnapshot(snapshot);

    Updater alwaysVerifyUpdater =
        Updater.builder()
            .setClock(Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC))
            .setVerifiers(key -> (digest, signature) -> true)
            .setMetaFetcher(metaFetcher)
            .setTargetFetcher(targetFetcher)
            .setTrustedRootPath(rootProvider)
            .setTrustedMetaStore(trustedMetaStore)
            .setTargetStore(targetStore)
            .build();

    // Initialize updateStartTime by calling updateRoot
    when(rootProvider.get())
        .thenReturn(
            Resources.toString(
                Resources.getResource("dev/sigstore/tuf/model/root.json"),
                Charset.defaultCharset()));
    when(metaFetcher.getRootAtVersion(anyInt())).thenReturn(Optional.empty());
    alwaysVerifyUpdater.updateRoot();

    return alwaysVerifyUpdater;
  }

  /**
   * Updates the snapshot in the trusted store to have correct hashes for a given delegated role's
   * metadata bytes.
   */
  private void mockSnapshotForRole(String roleName, byte[] roleBytes, int version)
      throws Exception {
    // Read current snapshot, update hashes for the role
    String snapshotJson =
        Resources.toString(
            Resources.getResource("dev/sigstore/tuf/model/snapshot.json"),
            Charset.defaultCharset());

    // The snapshot already has entries for rekor, staging, revocation.
    // We need to update the hashes to match our mock bytes.
    // Re-parse and re-store the snapshot with updated hashes for this role.
    Snapshot snapshot = trustedMetaStore.getSnapshot();
    var meta = new java.util.HashMap<>(snapshot.getSignedMeta().getMeta());
    var existingEntry = meta.get(roleName + ".json");
    if (existingEntry != null) {
      // Build updated entry with correct hashes for our mock bytes
      String sha256 = com.google.common.hash.Hashing.sha256().hashBytes(roleBytes).toString();
      String sha512 = com.google.common.hash.Hashing.sha512().hashBytes(roleBytes).toString();
      String updatedSnapshotJson =
          "{"
              + "  \"signatures\": [{\"keyid\": \"fc61191ba8a516fe386c7d6c97d918e1d241e1589729add09b122725b8c32451\", \"sig\": \"deadbeef\"}],"
              + "  \"signed\": {"
              + "    \"_type\": \"snapshot\","
              + "    \"expires\": \"2030-01-01T00:00:00Z\","
              + "    \"meta\": {";

      // Rebuild all meta entries, updating the target role
      for (var entry : meta.entrySet()) {
        String key = entry.getKey();
        var val = entry.getValue();
        if (key.equals(roleName + ".json")) {
          updatedSnapshotJson +=
              "\""
                  + key
                  + "\": {"
                  + "\"hashes\": {\"sha256\": \""
                  + sha256
                  + "\", \"sha512\": \""
                  + sha512
                  + "\"},"
                  + "\"length\": "
                  + roleBytes.length
                  + ","
                  + "\"version\": "
                  + version
                  + "},";
        } else {
          updatedSnapshotJson += "\"" + key + "\": {" + "\"version\": " + val.getVersion() + "},";
        }
      }
      // Remove trailing comma
      updatedSnapshotJson = updatedSnapshotJson.replaceAll(",$", "");
      updatedSnapshotJson +=
          "    }," + "    \"spec_version\": \"1.0\"," + "    \"version\": 41" + "  }" + "}";
      Snapshot updatedSnapshot = GSON.get().fromJson(updatedSnapshotJson, Snapshot.class);
      trustedMetaStore.setSnapshot(updatedSnapshot);
    }
  }
}
