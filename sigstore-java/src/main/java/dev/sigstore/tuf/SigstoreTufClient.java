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
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import dev.sigstore.trustroot.LegacySigningConfig;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreSigningConfig;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;

/**
 * Wrapper around {@link dev.sigstore.tuf.Updater} that provides access to sigstore specific
 * metadata items in a convenient API.
 */
public class SigstoreTufClient {

  @VisibleForTesting static final String TRUST_ROOT_FILENAME = "trusted_root.json";
  @VisibleForTesting static final String SIGNING_CONFIG_FILENAME = "signing_config.json";

  public static final String PUBLIC_GOOD_ROOT_RESOURCE =
      "dev/sigstore/tuf/sigstore-tuf-root/root.json";
  public static final String STAGING_ROOT_RESOURCE = "dev/sigstore/tuf/tuf-root-staging/root.json";

  private final Updater updater;
  private Instant lastUpdate;
  private SigstoreTrustedRoot sigstoreTrustedRoot;
  private SigstoreSigningConfig sigstoreSigningConfig;
  private SigstoreSigningConfig
      fallbackSigningConfig; // for tuf roots that don't quite support the trusted root yet
  private final Duration cacheValidity;

  @VisibleForTesting
  SigstoreTufClient(Updater updater, Duration cacheValidity) {
    this.updater = updater;
    this.cacheValidity = cacheValidity;
  }

  // TODO: remove this when we can guarantee we'll get a signing config from our tuf repos
  private SigstoreTufClient(
      Updater updater, Duration cacheValidity, SigstoreSigningConfig fallbackSigningConfig) {
    this.updater = updater;
    this.cacheValidity = cacheValidity;
    this.fallbackSigningConfig = fallbackSigningConfig;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    Duration cacheValidity = Duration.ofDays(1);
    Path tufCacheLocation =
        Path.of(System.getProperty("user.home")).resolve(".sigstore-java").resolve("root");

    private URL remoteMirror;
    private RootProvider trustedRoot;
    private SigstoreSigningConfig fallbackSigningConfig;

    public Builder usePublicGoodInstance() {
      if (remoteMirror != null || trustedRoot != null) {
        throw new IllegalStateException(
            "Using public good after configuring remoteMirror and trustedRoot");
      }
      try {
        tufMirror(
            new URL("https://tuf-repo-cdn.sigstore.dev/"),
            RootProvider.fromResource(PUBLIC_GOOD_ROOT_RESOURCE));
      } catch (MalformedURLException e) {
        throw new AssertionError(e);
      }
      fallbackSigningConfig = LegacySigningConfig.PUBLIC_GOOD;
      return this;
    }

    public Builder useStagingInstance() {
      if (remoteMirror != null || trustedRoot != null) {
        throw new IllegalStateException(
            "Using staging after configuring remoteMirror and trustedRoot");
      }
      try {
        tufMirror(
            new URL("https://tuf-repo-cdn.sigstage.dev"),
            RootProvider.fromResource(STAGING_ROOT_RESOURCE));
      } catch (MalformedURLException e) {
        throw new AssertionError(e);
      }
      tufCacheLocation =
          Path.of(System.getProperty("user.home"))
              .resolve(".sigstore-java")
              .resolve("staging")
              .resolve("root");
      fallbackSigningConfig = LegacySigningConfig.STAGING;
      return this;
    }

    public Builder tufMirror(URL mirror, RootProvider trustedRoot) {
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

    /**
     * For cases where the remote TUF repo doesn't yet contain a signing config, configure this
     * programmatically.
     */
    public Builder fallbackStagingConfig(SigstoreSigningConfig fallbackSigningConfig) {
      this.fallbackSigningConfig = fallbackSigningConfig;
      return this;
    }

    public SigstoreTufClient build() throws IOException {
      Preconditions.checkState(!cacheValidity.isNegative(), "cacheValidity must be non negative");
      Preconditions.checkNotNull(remoteMirror);
      Preconditions.checkNotNull(trustedRoot);
      if (!Files.isDirectory(tufCacheLocation)) {
        Files.createDirectories(tufCacheLocation);
      }
      var normalizedRemoteMirror =
          remoteMirror.toString().endsWith("/")
              ? remoteMirror
              : new URL(remoteMirror.toExternalForm() + "/");
      var remoteTargetsLocation = new URL(normalizedRemoteMirror.toExternalForm() + "targets");
      var filesystemTufStore = FileSystemTufStore.newFileSystemStore(tufCacheLocation);
      var tufUpdater =
          Updater.builder()
              .setTrustedRootPath(trustedRoot)
              .setTrustedMetaStore(
                  TrustedMetaStore.newTrustedMetaStore(
                      PassthroughCacheMetaStore.newPassthroughMetaCache(filesystemTufStore)))
              .setTargetStore(filesystemTufStore)
              .setMetaFetcher(
                  MetaFetcher.newFetcher(HttpFetcher.newFetcher(normalizedRemoteMirror)))
              .setTargetFetcher(HttpFetcher.newFetcher(remoteTargetsLocation))
              .build();
      return new SigstoreTufClient(tufUpdater, cacheValidity, fallbackSigningConfig);
    }
  }

  /**
   * Update the tuf metadata if the cache has not been updated for at least {@code cacheValidity}
   * defined on the client.
   */
  public void update()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          CertificateException, SigstoreConfigurationException {
    if (lastUpdate == null
        || Duration.between(lastUpdate, Instant.now()).compareTo(cacheValidity) > 0) {
      this.forceUpdate();
    }
  }

  /** Force an update, ignoring any cache validity. */
  public void forceUpdate()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          SigstoreConfigurationException {
    updater.update();
    lastUpdate = Instant.now();
    var trustedRootBuilder = TrustedRoot.newBuilder();
    JsonFormat.parser()
        .merge(
            new String(
                updater.getTargetStore().readTarget(TRUST_ROOT_FILENAME), StandardCharsets.UTF_8),
            trustedRootBuilder);
    sigstoreTrustedRoot = SigstoreTrustedRoot.from(trustedRootBuilder.build());
    // TODO: Remove when prod and staging TUF repos have fully configured signing configs
    try {
      sigstoreSigningConfig =
          SigstoreSigningConfig.from(
              updater.getTargetStore().getTargetInputSteam(SIGNING_CONFIG_FILENAME));
    } catch (Exception e) {
      sigstoreSigningConfig = fallbackSigningConfig;
    }
  }

  public SigstoreTrustedRoot getSigstoreTrustedRoot() {
    return sigstoreTrustedRoot;
  }

  public SigstoreSigningConfig getSigstoreSigningConfig() {
    return sigstoreSigningConfig;
  }
}
