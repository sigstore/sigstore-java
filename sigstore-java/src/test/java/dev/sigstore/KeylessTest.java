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
import dev.sigstore.bundle.Bundle;
import dev.sigstore.testkit.annotations.DisabledIfSkipStaging;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class KeylessTest {
  @TempDir public static Path testRoot;

  public static List<byte[]> artifactDigests;

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
  @EnabledIfOidcExists(provider = OidcProviderType.ANY)
  public void sign_production() throws Exception {
    var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
    var results = signer.sign(artifactDigests);

    verifySigningResult(results, false);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    for (int i = 0; i < results.size(); i++) {
      verifier.verify(artifactDigests.get(i), results.get(i), VerificationOptions.empty());
      checkBundleSerialization(results.get(i));
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  @EnabledIfOidcExists(provider = OidcProviderType.ANY)
  @DisabledIfSkipStaging
  public void sign_staging(boolean enableRekorV2) throws Exception {
    var signer =
        KeylessSigner.builder().sigstoreStagingDefaults().enableRekorV2(enableRekorV2).build();
    var results = signer.sign(artifactDigests);
    verifySigningResult(results, enableRekorV2);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    for (int i = 0; i < results.size(); i++) {
      verifier.verify(artifactDigests.get(i), results.get(i), VerificationOptions.empty());
      checkBundleSerialization(results.get(i));
    }
  }

  private void verifySigningResult(List<Bundle> results, boolean enableRekorV2) throws IOException {

    Assertions.assertEquals(artifactDigests.size(), results.size());

    for (int i = 0; i < results.size(); i++) {
      var result = results.get(i);
      var artifactDigest = artifactDigests.get(i);
      Assertions.assertNotNull(
          result.getMessageSignature().get().getMessageDigest().get().getDigest());
      Assertions.assertNotNull(result.getCertPath());
      Assertions.assertEquals(1, result.getEntries().size());
      Assertions.assertNotNull(result.getMessageSignature().get().getSignature());

      // check if the rekor entry has the digest we sent
      Assertions.assertArrayEquals(
          artifactDigest, result.getMessageSignature().get().getMessageDigest().get().getDigest());
      Assertions.assertEquals(
          AlgorithmRegistry.HashAlgorithm.SHA2_256,
          result.getMessageSignature().get().getMessageDigest().get().getHashAlgorithm());
      // check if required inclusion proof exists
      Assertions.assertNotNull(result.getEntries().get(0).getVerification().getInclusionProof());

      if (enableRekorV2) {
        Assertions.assertEquals(
            "0.0.2", result.getEntries().get(0).getBodyDecoded().getApiVersion());
      } else {
        Assertions.assertEquals(
            "0.0.1", result.getEntries().get(0).getBodyDecoded().getApiVersion());
      }
    }
  }

  private void checkBundleSerialization(Bundle bundle) throws Exception {
    var stringFromBundle = bundle.toJson();
    var bundleFromString = Bundle.from(new StringReader(stringFromBundle));
    var stringFromBundle2 = bundleFromString.toJson();
    Assertions.assertEquals(stringFromBundle, stringFromBundle2);
    Assertions.assertEquals(bundle, bundleFromString);
    // match mediatype
    Assertions.assertEquals(1, StringUtils.countMatches(stringFromBundle, "mediaType"));
    Assertions.assertTrue(
        stringFromBundle.contains(
            "\"mediaType\": \"application/vnd.dev.sigstore.bundle.v0.3+json\""));
  }
}
