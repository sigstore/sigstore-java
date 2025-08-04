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
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcTokenMatcher;
import dev.sigstore.oidc.client.TokenStringOidcClient;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.testing.matchers.ByteArrayListMatcher;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import dev.sigstore.testkit.oidc.ConformanceTestingTokenProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

/**
 * Actually workflow tests for signing are in {@link dev.sigstore.KeylessTest}. This is just tests
 * for the convenience wrappers.
 */
public class KeylessSignerTest {

  @TempDir public static Path testRoot;

  public static List<byte[]> artifactHashes;
  public static List<Path> artifacts;
  public static List<Bundle> signingResults;
  public static KeylessSigner signer;

  @BeforeAll
  public static void setup() throws Exception {
    artifactHashes = new ArrayList<>();
    artifacts = new ArrayList<>();
    signingResults = new ArrayList<>();
    for (int i = 0; i < 2; i++) {
      var artifact = testRoot.resolve("artifact" + i + ".e2e");
      Files.createFile(artifact);
      Files.write(
          artifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
      var hash =
          com.google.common.io.Files.asByteSource(artifact.toFile())
              .hash(Hashing.sha256())
              .asBytes();
      artifactHashes.add(hash);
      artifacts.add(artifact);
      signingResults.add(Mockito.mock(Bundle.class));
    }

    // make sure our mock signing results are not equal
    Assertions.assertNotEquals(signingResults.get(0), signingResults.get(1));

    signer = Mockito.spy(KeylessSigner.builder().sigstorePublicDefaults().build());
    Mockito.doReturn(signingResults.subList(0, 1))
        .when(signer)
        .sign(Mockito.argThat(new ByteArrayListMatcher(artifactHashes.subList(0, 1))));
    Mockito.doReturn(signingResults)
        .when(signer)
        .sign(Mockito.argThat(new ByteArrayListMatcher(artifactHashes)));
  }

  @Test
  public void sign_file() throws Exception {
    Assertions.assertEquals(signingResults.get(0), signer.signFile(artifacts.get(0)));
  }

  @Test
  public void sign_dssev2() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstoreStagingDefaults()
            .forceCredentialProviders(OidcClients.of(TokenStringOidcClient.from(ConformanceTestingTokenProvider.newProvider())))
            .build();
    var bundle =
        signer.attest(
            new String(
                Base64.decode(
                    "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiYS50eHQiLCJkaWdlc3QiOnsic2hhMjU2IjoiYTBjZmM3MTI3MWQ2ZTI3OGU1N2NkMzMyZmY5NTdjM2Y3MDQzZmRkYTM1NGM0Y2JiMTkwYTMwZDU2ZWZhMDFiZiJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vYWN0aW9ucy5naXRodWIuaW8vYnVpbGR0eXBlcy93b3JrZmxvdy92MSIsImV4dGVybmFsUGFyYW1ldGVycyI6eyJ3b3JrZmxvdyI6eyJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZXBvc2l0b3J5IjoiaHR0cHM6Ly9naXRodWIuY29tL2xvb3NlYmF6b29rYS9hYS10ZXN0IiwicGF0aCI6Ii5naXRodWIvd29ya2Zsb3dzL3Byb3ZlbmFuY2UueWFtbCJ9fSwiaW50ZXJuYWxQYXJhbWV0ZXJzIjp7ImdpdGh1YiI6eyJldmVudF9uYW1lIjoid29ya2Zsb3dfZGlzcGF0Y2giLCJyZXBvc2l0b3J5X2lkIjoiODkxNzE1NDQ0IiwicmVwb3NpdG9yeV9vd25lcl9pZCI6IjEzMDQ4MjYiLCJydW5uZXJfZW52aXJvbm1lbnQiOiJnaXRodWItaG9zdGVkIn19LCJyZXNvbHZlZERlcGVuZGVuY2llcyI6W3sidXJpIjoiZ2l0K2h0dHBzOi8vZ2l0aHViLmNvbS9sb29zZWJhem9va2EvYWEtdGVzdEByZWZzL2hlYWRzL21haW4iLCJkaWdlc3QiOnsiZ2l0Q29tbWl0IjoiZWJmZjhkZmJkNjA5YjdiMjIyMzdjNzcxOWNlMDdmMmRjNzkzNGY1ZiJ9fV19LCJydW5EZXRhaWxzIjp7ImJ1aWxkZXIiOnsiaWQiOiJodHRwczovL2dpdGh1Yi5jb20vbG9vc2ViYXpvb2thL2FhLXRlc3QvLmdpdGh1Yi93b3JrZmxvd3MvcHJvdmVuYW5jZS55YW1sQHJlZnMvaGVhZHMvbWFpbiJ9LCJtZXRhZGF0YSI6eyJpbnZvY2F0aW9uSWQiOiJodHRwczovL2dpdGh1Yi5jb20vbG9vc2ViYXpvb2thL2FhLXRlc3QvYWN0aW9ucy9ydW5zLzExOTQxNDI1NDg3L2F0dGVtcHRzLzEifX19fQ=="),
                StandardCharsets.UTF_8));
    var bundle2 =
        signer.attest(
            new String(
                Base64.decode(
                    "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiYS50eHQiLCJkaWdlc3QiOnsic2hhMjU2IjoiYTBjZmM3MTI3MWQ2ZTI3OGU1N2NkMzMyZmY5NTdjM2Y3MDQzZmRkYTM1NGM0Y2JiMTkwYTMwZDU2ZWZhMDFiZiJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vYWN0aW9ucy5naXRodWIuaW8vYnVpbGR0eXBlcy93b3JrZmxvdy92MSIsImV4dGVybmFsUGFyYW1ldGVycyI6eyJ3b3JrZmxvdyI6eyJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZXBvc2l0b3J5IjoiaHR0cHM6Ly9naXRodWIuY29tL21vb3NlL2FhLXRlc3QiLCJwYXRoIjoiLmdpdGh1Yi93b3JrZmxvd3MvcHJvdmVuYW5jZS55YW1sIn19LCJpbnRlcm5hbFBhcmFtZXRlcnMiOnsiZ2l0aHViIjp7ImV2ZW50X25hbWUiOiJ3b3JrZmxvd19kaXNwYXRjaCIsInJlcG9zaXRvcnlfaWQiOiI4OTE3MTU0NDQiLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiMTMwNDgyNiIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL21vb3NlL2FhLXRlc3RAcmVmcy9oZWFkcy9tYWluIiwiZGlnZXN0Ijp7ImdpdENvbW1pdCI6ImViZmY4ZGZiZDYwOWI3YjIyMjM3Yzc3MTljZTA3ZjJkYzc5MzRmNWYifX1dfSwicnVuRGV0YWlscyI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9naXRodWIuY29tL21vb3NlL2FhLXRlc3QvLmdpdGh1Yi93b3JrZmxvd3MvcHJvdmVuYW5jZS55YW1sQHJlZnMvaGVhZHMvbWFpbiJ9LCJtZXRhZGF0YSI6eyJpbnZvY2F0aW9uSWQiOiJodHRwczovL2dpdGh1Yi5jb20vbW9vc2UvYWEtdGVzdC9hY3Rpb25zL3J1bnMvMTE5NDE0MjU0ODcvYXR0ZW1wdHMvMSJ9fX19Cg=="),
                StandardCharsets.UTF_8));
    System.out.println("====================== bundle 1 =======================");
    System.out.println(bundle.toJson());
    System.out.println("====================== bundle 2 =======================");
    System.out.println(bundle2.toJson());
  }

  @Test
  public void sign_files() throws Exception {
    var signingResultsMap = new HashMap<Path, Bundle>();
    for (int i = 0; i < signingResults.size(); i++) {
      signingResultsMap.put(artifacts.get(i), signingResults.get(i));
    }
    Assertions.assertEquals(signingResultsMap, signer.signFiles(artifacts));
  }

  @Test
  public void sign_digest() throws Exception {
    Assertions.assertEquals(signingResults.get(0), signer.sign(artifactHashes.get(0)));
  }

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  public void sign_failGithubOidcCheck() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstorePublicDefaults()
            .allowedOidcIdentities(
                List.of(
                    OidcTokenMatcher.of(
                        StringMatcher.string("goose@goose.com"),
                        StringMatcher.string("goose.com"))))
            .build();
    var ex =
        Assertions.assertThrows(
            KeylessSignerException.class,
            () ->
                signer.sign(
                    Hex.decode(
                        "10f26b52447ec6427c178cadb522ce649922ee67f6d59709e45700aa5df68b30")));
    MatcherAssert.assertThat(ex.getMessage(), CoreMatchers.startsWith("Obtained Oidc Token"));
    MatcherAssert.assertThat(
        ex.getMessage(), CoreMatchers.endsWith("does not match any identities in allow list"));
  }

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.GITHUB)
  // this test will only pass on the github.com/sigstore/sigstore-java repository
  public void sign_passGithubOidcCheck() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstorePublicDefaults()
            .allowedOidcIdentities(
                List.of(
                    OidcTokenMatcher.of(
                        // this is bad matching, do not use it as an example of what to do in a
                        // production environment
                        StringMatcher.regex(".*sigstore/sigstore-java.*"),
                        StringMatcher.string("https://token.actions.githubusercontent.com")),
                    OidcTokenMatcher.of(
                        StringMatcher.string("some@other.com"),
                        StringMatcher.string("https://accounts.other.com"))))
            .build();
    Assertions.assertDoesNotThrow(
        () ->
            signer.sign(
                Hex.decode("10f26b52447ec6427c178cadb522ce649922ee67f6d59709e45700aa5df68b30")));
  }
}
