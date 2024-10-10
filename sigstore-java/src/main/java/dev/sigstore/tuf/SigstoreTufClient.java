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

  public static final String PUBLIC_GOOD_ROOT_RESOURCE =
      "dev/sigstore/tuf/sigstore-tuf-root/root.json";
  public static final String STAGING_ROOT_RESOURCE = "dev/sigstore/tuf/tuf-root-staging/root.json";

  private final Updater updater;
  private Instant lastUpdate;
  private SigstoreTrustedRoot sigstoreTrustedRoot;
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

    URL remoteMirror;
    RootProvider trustedRoot;

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
      var targetsLocation = new URL(normalizedRemoteMirror.toExternalForm() + "targets");
      var tufUpdater =
          Updater.builder()
              .setTrustedRootPath(trustedRoot)
              .setLocalStore(FileSystemTufStore.newFileSystemStore(tufCacheLocation))
              .setMetaFetcher(
                  MetaFetcher.newFetcher(HttpFetcher.newFetcher(normalizedRemoteMirror)))
              .setTargetFetcher(HttpFetcher.newFetcher(targetsLocation))
              .build();
      return new SigstoreTufClient(tufUpdater, cacheValidity);
    }
  }

  /**
   * Update the tuf metadata if the cache has not been updated for at least {@code cacheValidity}
   * defined on the client.
   */
  public void update()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          CertificateException {
    if (lastUpdate == null
        || Duration.between(lastUpdate, Instant.now()).compareTo(cacheValidity) > 0) {
      this.forceUpdate();
    }
  }

  /** Force an update, ignoring any cache validity. */
  public void forceUpdate()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
          CertificateException {
    updater.update();
    lastUpdate = Instant.now();
    var trustedRootBuilder = TrustedRoot.newBuilder();
    JsonFormat.parser()
        .merge(
            new String(
                updater.getLocalStore().getTargetFile(TRUST_ROOT_FILENAME), StandardCharsets.UTF_8),
            trustedRootBuilder);
    sigstoreTrustedRoot = SigstoreTrustedRoot.from(trustedRootBuilder.build());
  }

  public SigstoreTrustedRoot getSigstoreTrustedRoot() {
    return sigstoreTrustedRoot;
  }
}
