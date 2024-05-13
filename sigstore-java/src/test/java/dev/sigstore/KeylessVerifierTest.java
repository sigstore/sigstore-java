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
package dev.sigstore;

import com.google.common.io.Resources;
import dev.sigstore.KeylessVerificationRequest.VerificationOptions;
import dev.sigstore.bundle.Bundle;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class KeylessVerifierTest {

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void testVerify_noDigestInBundle(boolean isOnline) throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-no-digest.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var verificationReq =
        KeylessVerificationRequest.builder()
            .keylessSignature(Bundle.from(new StringReader(bundleFile)).toKeylessSignature())
            .verificationOptions(
                VerificationOptions.builder().alwaysUseRemoteRekorEntry(isOnline).build())
            .build();
    verifier.verify(Path.of(artifact), verificationReq);
  }

  @Test
  public void testVerify_mismatchedSet() throws Exception {
    // a bundle file where the SET is replaced with a valid SET for another artifact
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-mismatched-set.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var verificationReq =
        KeylessVerificationRequest.builder()
            .keylessSignature(Bundle.from(new StringReader(bundleFile)).toKeylessSignature())
            .build();
    Assertions.assertThrows(
        KeylessVerificationException.class,
        () -> verifier.verify(Path.of(artifact), verificationReq));
  }

  @Test
  public void testVerify_canVerifyV01Bundle() throws Exception {
    // note that this v1 bundle contains an inclusion proof
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v1.sigstore");
  }

  @Test
  public void testVerify_canVerifyV02Bundle() throws Exception {
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v2.sigstore");
  }

  @Test
  public void testVerify_canVerifyV03Bundle() throws Exception {
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v3.sigstore");
  }

  public void verifyBundle(String artifactResourcePath, String bundleResourcePath)
      throws Exception {
    var artifact = Resources.getResource(artifactResourcePath).getPath();
    var bundleFile =
        Resources.toString(Resources.getResource(bundleResourcePath), StandardCharsets.UTF_8);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var verificationReq =
        KeylessVerificationRequest.builder()
            .keylessSignature(Bundle.from(new StringReader(bundleFile)).toKeylessSignature())
            .verificationOptions(VerificationOptions.builder().build())
            .build();

    verifier.verify(Path.of(artifact), verificationReq);
  }
}
