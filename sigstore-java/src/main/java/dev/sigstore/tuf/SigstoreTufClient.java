package dev.sigstore.tuf;

import com.google.common.base.Preconditions;
import com.google.common.io.Resources;
import dev.sigstore.tuf.model.TargetMeta;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class SigstoreTufClient {

  private Updater updater;
  private Instant lastUpdate;
  private Map<String, byte[]> urlToKey = new HashMap<>();


  private SigstoreTufClient(Updater updater) {
    this.updater = updater;
  }

  public static class Builder {
    int cacheValidityDays = 1;
    Path tufCacheLocation = Path.of("~/.sigstore-java/root");

    URL remoteMirror;
    Path trustedRoot;

    public Builder usePublicGoodInstance() {
      if (remoteMirror != null || trustedRoot != null) {
        throw new IllegalStateException();
      }
      try {5
        tufMirror(new URL("https://storage.googleapis.com/sigstore-tuf-root/"), Path.of(Resources.getResource("dev/sigstore/tuf/sigstore-tuf-root/root.json").getPath()));
      } catch (MalformedURLException e) {
        throw new AssertionError(e);
      }
      return this;
    }

    public Builder tufMirror(URL mirror, Path trustedRoot) {
      this.remoteMirror = mirror;
      this.trustedRoot = trustedRoot;
      return this;
    }

    public Builder cacheValidation(int days) {
      this.cacheValidityDays = days;
      return this;
    }

    public Builder tufCacheLocation(Path location) {
      this.tufCacheLocation = location;
      return this;
    }

    public SigstoreTufClient build() throws IOException {
      Preconditions.checkState(cacheValidityDays > 0);
      Preconditions.checkNotNull(remoteMirror);
      Preconditions.checkNotNull(trustedRoot);
      if (!Files.isDirectory(tufCacheLocation)) {
        Files.createDirectories(tufCacheLocation);
      }
      var tufUpdater = Updater.builder().setTrustedRootPath(trustedRoot).setLocalStore(FileSystemTufStore.newFileSystemStore(tufCacheLocation)).setFetcher(HttpMetaFetcher.newFetcher(remoteMirror)).build();
      return new SigstoreTufClient(tufUpdater);
    }

  }

  public void initialize() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    updater.update();
  }

  public void update() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    updater.update();
    lastUpdate = Instant.now();
    urlToKey.clear();
    var targets = updater.getLocalStore().loadTargets().get().getSignedMeta().getTargets();
    for (String fileName : targets.keySet()) {
      TargetMeta.SigstoreMeta targetMeta = targets.get(fileName).getCustom().get().getSigstoreMeta();
      if (targetMeta.getStatus().equals("ACTIVE")) {
        urlToKey.put(targetMeta.getUri().get(), updater.getLocalStore().getTargetFile(fileName));
      }
    }
  }

  public Function<String, byte[]> getKeySupplier() {
      return new Function<>() {
        @Override
        public byte[] apply(String input) {
          return urlToKey.get(input);
        }
      };
  }
}
