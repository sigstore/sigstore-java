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
import dev.sigstore.oidc.client.OidcTokenMatcher;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.testing.matchers.ByteArrayListMatcher;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
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
