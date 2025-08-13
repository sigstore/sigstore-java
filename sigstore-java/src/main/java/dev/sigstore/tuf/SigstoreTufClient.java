/*
 * Copyright 2023 The Sigstore Authors.
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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import dev.sigstore.http.URIFormat;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;

/**
 * Wrapper around {@link dev.sigstore.tuf.Updater} that provides access to sigstore specific
 * metadata items in a convenient API.
 */
public class SigstoreTufClient {

  @VisibleForTesting static final String TRUST_ROOT_FILENAME = "trusted_root.json";
  @VisibleForTesting static final String SIGNING_CONFIG_FILENAME = "signing_config.v0.2.json";

  public static final String PUBLIC_GOOD_ROOT_RESOURCE =
      "dev/sigstore/tuf/sigstore-tuf-root/root.json";
  public static final String STAGING_ROOT_RESOURCE = "dev/sigstore/tuf/tuf-root-staging/root.json";

  private final Updater updater;
  private Instant lastUpdate;
  private SigstoreTrustedRoot sigstoreTrustedRoot;
  private SigstoreSigningConfig sigstoreSigningConfig;
  private final Duration cacheValidity;

  @VisibleForTesting
  SigstoreTufClient(Updater updater, Duration cacheValidity) {
    this.updater = updater;
    this.cacheValidity = cacheValidity;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    Duration cacheValidity = Duration.ofDays(1);
    Path tufCacheLocation =
        Path.of(System.getProperty("user.home")).resolve(".sigstore-java").resolve("root");

    private URI remoteMirror;
    private RootProvider trustedRoot;

    public Builder usePublicGoodInstance() {
      if (remoteMirror != null || trustedRoot != null) {
        throw new IllegalStateException(
            "Using public good after configuring remoteMirror and trustedRoot");
      }
      tufMirror(
          URI.create("https://tuf-repo-cdn.sigstore.dev/"),
          RootProvider.fromResource(PUBLIC_GOOD_ROOT_RESOURCE));
      return this;
    }

    public Builder useStagingInstance() {
      if (remoteMirror != null || trustedRoot != null) {
        throw new IllegalStateException(
            "Using staging after configuring remoteMirror and trustedRoot");
      }
      tufMirror(
          URI.create("https://tuf-repo-cdn.sigstage.dev"),
          RootProvider.fromResource(STAGING_ROOT_RESOURCE));
      tufCacheLocation =
          Path.of(System.getProperty("user.home"))
              .resolve(".sigstore-java")
              .resolve("staging")
              .resolve("root");
      return this;
    }

    public Builder tufMirror(URI mirror, RootProvider trustedRoot) {
      this.remoteMirror = mirror;
      this.trustedRoot = trustedRoot;
      return this;
    }

    public Builder cacheValidity(Duration duration) {
      this.cacheValidity = duration;
      return this;
    }

    public Builder tufCacheLocation(Path location) {
      this.tufCacheLocation = location;
      return this;
    }

    public SigstoreTufClient build() throws IOException {
      Preconditions.checkState(!cacheValidity.isNegative(), "cacheValidity must be non negative");
      Preconditions.checkNotNull(remoteMirror);
      Preconditions.checkNotNull(trustedRoot);
      if (!Files.isDirectory(tufCacheLocation)) {
        Files.createDirectories(tufCacheLocation);
      }
      var remoteTargetsLocation = URIFormat.appendPath(remoteMirror, "targets");
      var filesystemTufStore = FileSystemTufStore.newFileSystemStore(tufCacheLocation);
      var tufUpdater =
          Updater.builder()
              .setTrustedRootPath(trustedRoot)
              .setTrustedMetaStore(
                  TrustedMetaStore.newTrustedMetaStore(
                      PassthroughCacheMetaStore.newPassthroughMetaCache(filesystemTufStore)))
              .setTargetStore(filesystemTufStore)
              .setMetaFetcher(MetaFetcher.newFetcher(HttpFetcher.newFetcher(remoteMirror)))
              .setTargetFetcher(HttpFetcher.newFetcher(remoteTargetsLocation))
              .build();
      return new SigstoreTufClient(tufUpdater, cacheValidity);
    }
  }

  /**
   * Update the tuf metadata if the cache has not been updated for at least {@code cacheValidity}
   * defined on the client.
   */
  public void update() throws SigstoreConfigurationException {
    if (lastUpdate == null
        || Duration.between(lastUpdate, Instant.now()).compareTo(cacheValidity) > 0) {
      this.forceUpdate();
    }
  }

  /** Force an update, ignoring any cache validity. */
  public void forceUpdate() throws SigstoreConfigurationException {
    try {
      updater.update();
    } catch (IOException
        | NoSuchAlgorithmException
        | InvalidKeySpecException
        | InvalidKeyException ex) {
      throw new SigstoreConfigurationException("TUF repo failed to update", ex);
    }
    lastUpdate = Instant.now();
    try {
      sigstoreTrustedRoot =
          SigstoreTrustedRoot.from(
              updater.getTargetStore().getTargetInputSteam(TRUST_ROOT_FILENAME));
    } catch (IOException ex) {
      throw new SigstoreConfigurationException("Failed to read trusted root from target store", ex);
    }
    try {
      sigstoreSigningConfig =
          SigstoreSigningConfig.from(
              updater.getTargetStore().getTargetInputSteam(SIGNING_CONFIG_FILENAME));
    } catch (IOException ex) {
      throw new SigstoreConfigurationException(
          "Failed to read signing config from target store", ex);
    }
  }

  public SigstoreTrustedRoot getSigstoreTrustedRoot() {
    return sigstoreTrustedRoot;
  }

  public SigstoreSigningConfig getSigstoreSigningConfig() {
    return sigstoreSigningConfig;
  }
}
