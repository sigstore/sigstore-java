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

import com.google.common.hash.Hashing;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import dev.sigstore.rekor.client.RekorTypeException;
import dev.sigstore.rekor.client.RekorTypes;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessTest {
  @TempDir public static Path testRoot;

  public static List<byte[]> artifactDigests;
  public static List<Path> artifacts;

  @BeforeAll
  public static void setupArtifact() throws IOException {
    artifactDigests = new ArrayList<>();

    for (int i = 0; i < 2; i++) {
      var artifact = testRoot.resolve("artifact" + i + ".e2e");
      Files.createFile(artifact);
      Files.write(
          artifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
      var digest =
          com.google.common.io.Files.asByteSource(artifact.toFile())
              .hash(Hashing.sha256())
              .asBytes();
      artifactDigests.add(digest);
    }
  }

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.MANUAL)
  public void sign_production() throws Exception {
    var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
    var results = signer.sign(artifactDigests);

    verifySigningResult(results);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    for (var result : results) {
      verifier.verifyOnline(
          Hex.decode(result.getDigest()),
          Certificates.toPemBytes(result.getCertPath()),
          result.getSignature());
    }
  }

  @Test
  @Disabled("Temporary disable staging tests")
  @EnabledIfOidcExists(provider = OidcProviderType.MANUAL)
  public void sign_staging() throws Exception {
    var signer = KeylessSigner.builder().sigstoreStagingDefaults().build();
    var results = signer.sign(artifactDigests);
    verifySigningResult(results);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    for (var result : results) {
      verifier.verifyOnline(
          Hex.decode(result.getDigest()),
          Certificates.toPemBytes(result.getCertPath()),
          result.getSignature());
    }
  }

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  public void sign_productionWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstorePublicDefaults()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    var results = signer.sign(artifactDigests);
    verifySigningResult(results);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    for (var result : results) {
      verifier.verifyOnline(
          Hex.decode(result.getDigest()),
          Certificates.toPemBytes(result.getCertPath()),
          result.getSignature());
    }
  }

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  public void sign_stagingWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstoreStagingDefaults()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    var results = signer.sign(artifactDigests);
    verifySigningResult(results);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    for (var result : results) {
      verifier.verifyOnline(
          Hex.decode(result.getDigest()),
          Certificates.toPemBytes(result.getCertPath()),
          result.getSignature());
    }
  }

  private void verifySigningResult(List<KeylessSigningResult> results)
      throws IOException, RekorTypeException {

    Assertions.assertEquals(artifactDigests.size(), results.size());

    for (int i = 0; i < results.size(); i++) {
      var result = results.get(i);
      var artifactDigest = artifactDigests.get(i);
      Assertions.assertNotNull(result.getDigest());
      Assertions.assertNotNull(result.getCertPath());
      Assertions.assertNotNull(result.getEntry());
      Assertions.assertNotNull(result.getSignature());

      var hr = RekorTypes.getHashedRekord(result.getEntry());
      // check if ht rekor entry has the digest we sent
      Assertions.assertEquals(Hex.toHexString(artifactDigest), result.getDigest());
      // check if the rekor entry has the signature we sent
      Assertions.assertArrayEquals(
          Base64.getDecoder().decode(hr.getSignature().getContent()), result.getSignature());
      // check if the rekor entry has the certificate we sent
      Assertions.assertArrayEquals(
          Base64.getDecoder().decode(hr.getSignature().getPublicKey().getContent()),
          Certificates.toPemBytes(result.getCertPath().getCertificates().get(0)));
    }
  }
}
