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
package dev.sigstore;

import dev.sigstore.oidc.client.GithubActionsOidcClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessSignerTest {

  @TempDir public static Path testRoot;
  public static Path testArtifact;

  @BeforeAll
  public static void setupArtifact() throws IOException {
    testArtifact = testRoot.resolve("artifact.e2e");
    Files.createFile(testArtifact);
    Files.write(
        testArtifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
  }

  @Test
  @Tag("manual")
  public void sign_production() throws Exception {
    var signer = KeylessSigner.builderForProd().build();
    signer.sign(testArtifact);
  }

  @Test
  @Tag("manual")
  public void sign_staging() throws Exception {
    var signer = KeylessSigner.builderForStaging().build();
    signer.sign(testArtifact);
  }

  @Test
  @Tag("github_oidc")
  public void sign_productionWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builderForProd()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    signer.sign(testArtifact);
  }

  @Test
  @Tag("github_oidc")
  public void sign_stagingWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builderForStaging()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    signer.sign(testArtifact);
  }
}
