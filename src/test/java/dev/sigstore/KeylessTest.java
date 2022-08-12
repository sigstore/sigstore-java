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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessTest {

  @TempDir public static Path testRoot;
  public static Path testArtifact;
  public static String testArtifactDigest;

  @BeforeAll
  public static void setupArtifact() throws IOException {
    testArtifact = testRoot.resolve("artifact.e2e");
    Files.createFile(testArtifact);
    Files.write(
        testArtifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
    var artifactByteSource = com.google.common.io.Files.asByteSource(testArtifact.toFile());
    var artifactDigest = artifactByteSource.hash(Hashing.sha256()).asBytes();
    testArtifactDigest = Hex.toHexString(artifactDigest);
  }

  @Test
  @Tag("manual")
  public void sign_production() throws Exception {
    var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
    var result = signer.sign(testArtifact);

    verifySigningResult(result);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verifyOnline(
        Hex.decode(result.getDigest()),
        Certificates.toPemBytes(result.getCertPath()),
        result.getSignature());
  }

  @Test
  @Tag("manual")
  public void sign_staging() throws Exception {
    var signer = KeylessSigner.builder().sigstoreStagingDefaults().build();
    var result = signer.sign(testArtifact);
    verifySigningResult(result);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    verifier.verifyOnline(
        Hex.decode(result.getDigest()),
        Certificates.toPemBytes(result.getCertPath()),
        result.getSignature());
  }

  @Test
  @Tag("github_oidc")
  public void sign_productionWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstorePublicDefaults()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    var result = signer.sign(testArtifact);
    verifySigningResult(result);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verifyOnline(
        Hex.decode(result.getDigest()),
        Certificates.toPemBytes(result.getCertPath()),
        result.getSignature());
  }

  @Test
  @Tag("github_oidc")
  public void sign_stagingWithGithubOidc() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstoreStagingDefaults()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    var result = signer.sign(testArtifact);
    verifySigningResult(result);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    verifier.verifyOnline(
        Hex.decode(result.getDigest()),
        Certificates.toPemBytes(result.getCertPath()),
        result.getSignature());
  }

  private void verifySigningResult(KeylessSigningResult result)
      throws IOException, RekorTypeException {
    Assertions.assertNotNull(result.getDigest());
    Assertions.assertNotNull(result.getCertPath());
    Assertions.assertNotNull(result.getEntry());
    Assertions.assertNotNull(result.getSignature());

    var hr = RekorTypes.getHashedRekord(result.getEntry());
    // check if ht rekor entry has the digest we sent
    Assertions.assertEquals(testArtifactDigest, result.getDigest());
    // check if the rekor entry has the signature we sent
    Assertions.assertArrayEquals(
        Base64.getDecoder().decode(hr.getSignature().getContent()), result.getSignature());
    // check if the rekor entry has the certificate we sent
    Assertions.assertArrayEquals(
        Base64.getDecoder().decode(hr.getSignature().getPublicKey().getContent()),
        Certificates.toPemBytes(result.getCertPath().getCertificates().get(0)));
  }
}
