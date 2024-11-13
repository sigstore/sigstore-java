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
package dev.sigstore.tuf.cli;

import dev.sigstore.tuf.FileSystemTufStore;
import dev.sigstore.tuf.HttpFetcher;
import dev.sigstore.tuf.MetaFetcher;
import dev.sigstore.tuf.PassthroughCacheMetaStore;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.TrustedMetaStore;
import dev.sigstore.tuf.Updater;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;

@Command(name = "download", description = "download targets from a remote location")
public class Download implements Callable<Integer> {

  @ParentCommand private Tuf tufCommand;

  @Override
  public Integer call() throws Exception {
    var metadataDir = tufCommand.getMetadataDir();
    var metadataUrl = tufCommand.getMetadataUrl();
    var targetDir = tufCommand.getTargetDir();
    var targetBaseUrl = tufCommand.getTargetBaseUrl();
    var targetName = tufCommand.getTargetName();

    var fsStore = FileSystemTufStore.newFileSystemStore(metadataDir, targetDir);
    var tuf =
        Updater.builder()
            .setTrustedMetaStore(
                TrustedMetaStore.newTrustedMetaStore(
                    PassthroughCacheMetaStore.newPassthroughMetaCache(fsStore)))
            .setTrustedRootPath(RootProvider.fromFile(metadataDir.resolve("root.json")))
            .setMetaFetcher(MetaFetcher.newFetcher(HttpFetcher.newFetcher(metadataUrl)))
            .setTargetFetcher(HttpFetcher.newFetcher(targetBaseUrl))
            .setTargetStore(fsStore)
            .build();
    // the java client isn't one shot like other clients, so downloadTarget doesn't call update
    // for the sake of conformance updateMeta here
    tuf.updateMeta();
    tuf.downloadTarget(targetName);
    return 0;
  }
}
