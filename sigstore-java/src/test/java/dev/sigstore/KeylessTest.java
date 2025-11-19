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
import dev.sigstore.dsse.InTotoPayload;
import dev.sigstore.json.JsonParseException;
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
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class KeylessTest {
  @TempDir public static Path testRoot;

  public static List<byte[]> artifactDigests;
  public static String payload;

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

    payload =
        new String(
            Base64.decode(
                "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiYS50eHQiLCJkaWdlc3QiOnsic2hhMjU2IjoiYTBjZmM3MTI3MWQ2ZTI3OGU1N2NkMzMyZmY5NTdjM2Y3MDQzZmRkYTM1NGM0Y2JiMTkwYTMwZDU2ZWZhMDFiZiJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vYWN0aW9ucy5naXRodWIuaW8vYnVpbGR0eXBlcy93b3JrZmxvdy92MSIsImV4dGVybmFsUGFyYW1ldGVycyI6eyJ3b3JrZmxvdyI6eyJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZXBvc2l0b3J5IjoiaHR0cHM6Ly9naXRodWIuY29tL2xvb3NlYmF6b29rYS9hYS10ZXN0IiwicGF0aCI6Ii5naXRodWIvd29ya2Zsb3dzL3Byb3ZlbmFuY2UueWFtbCJ9fSwiaW50ZXJuYWxQYXJhbWV0ZXJzIjp7ImdpdGh1YiI6eyJldmVudF9uYW1lIjoid29ya2Zsb3dfZGlzcGF0Y2giLCJyZXBvc2l0b3J5X2lkIjoiODkxNzE1NDQ0IiwicmVwb3NpdG9yeV9vd25lcl9pZCI6IjEzMDQ4MjYiLCJydW5uZXJfZW52aXJvbm1lbnQiOiJnaXRodWItaG9zdGVkIn19LCJyZXNvbHZlZERlcGVuZGVuY2llcyI6W3sidXJpIjoiZ2l0K2h0dHBzOi8vZ2l0aHViLmNvbS9sb29zZWJhem9va2EvYWEtdGVzdEByZWZzL2hlYWRzL21haW4iLCJkaWdlc3QiOnsiZ2l0Q29tbWl0IjoiZWJmZjhkZmJkNjA5YjdiMjIyMzdjNzcxOWNlMDdmMmRjNzkzNGY1ZiJ9fV19LCJydW5EZXRhaWxzIjp7ImJ1aWxkZXIiOnsiaWQiOiJodHRwczovL2dpdGh1Yi5jb20vbG9vc2ViYXpvb2thL2FhLXRlc3QvLmdpdGh1Yi93b3JrZmxvd3MvcHJvdmVuYW5jZS55YW1sQHJlZnMvaGVhZHMvbWFpbiJ9LCJtZXRhZGF0YSI6eyJpbnZvY2F0aW9uSWQiOiJodHRwczovL2dpdGh1Yi5jb20vbG9vc2ViYXpvb2thL2FhLXRlc3QvYWN0aW9ucy9ydW5zLzExOTQxNDI1NDg3L2F0dGVtcHRzLzEifX19fQ=="),
            StandardCharsets.UTF_8);
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

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.ANY)
  @DisabledIfSkipStaging
  public void attest_staging() throws Exception {
    var signer = KeylessSigner.builder().sigstoreStagingDefaults().enableRekorV2(true).build();
    var result = signer.attest(payload);

    Assertions.assertNotNull(result.getDsseEnvelope().get());
    Assertions.assertEquals(payload, result.getDsseEnvelope().get().getPayloadAsString());
    Assertions.assertEquals(1, result.getEntries().size());
    Assertions.assertEquals("0.0.2", result.getEntries().get(0).getBodyDecoded().getApiVersion());

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var intotoPayload = InTotoPayload.from(result.getDsseEnvelope().get());
    var artifactDigest = Hex.decode(intotoPayload.getSubject().get(0).getDigest().get("sha256"));
    verifier.verify(artifactDigest, result, VerificationOptions.empty());
    checkBundleSerialization(result);
  }

  private void verifySigningResult(List<Bundle> results, boolean enableRekorV2)
      throws IOException, JsonParseException {

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
