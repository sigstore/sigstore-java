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
package dev.sigstore.rekor.client;

import com.google.common.io.Resources;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RekorVerifierTest {
  public String rekorResponse;
  public String rekorQueryResponse;
  public byte[] rekorPub;

  @BeforeEach
  public void loadResources() throws IOException {
    rekorResponse =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/response.json"),
            StandardCharsets.UTF_8);
    rekorPub =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/rekor.pub"));
    rekorQueryResponse =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/query-response.json"),
            StandardCharsets.UTF_8);
  }

  @Test
  public void verifyEntry_valid()
      throws URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException, IOException,
          RekorVerificationException, SignatureException, InvalidKeyException {
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), rekorResponse);
    var verifier = RekorVerifier.newRekorVerifier(rekorPub);

    verifier.verifyEntry(response.getEntry());
  }

  @Test
  public void verifyEntry_invalid()
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {
    // change the logindex
    var invalidResponse = rekorResponse.replace("79", "80");
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), invalidResponse);
    var verifier = RekorVerifier.newRekorVerifier(rekorPub);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(response.getEntry()));
    Assertions.assertEquals("Entry SET was not valid", thrown.getMessage());
  }

  @Test
  public void verifyEntry_withInclusionProof()
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException,
          RekorVerificationException, SignatureException, InvalidKeyException, URISyntaxException {
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), rekorQueryResponse);
    var verifier = RekorVerifier.newRekorVerifier(rekorPub);

    var entry = response.getEntry();
    verifier.verifyEntry(entry);
    verifier.verifyInclusionProof(entry);
  }

  @Test
  public void verifyEntry_withInvalidInclusionProof()
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException,
          RekorVerificationException, SignatureException, InvalidKeyException, URISyntaxException {
    // replace a hash in the inclusion proof to make it bad
    var invalidResponse = rekorQueryResponse.replace("b4439e", "aaaaaa");

    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), invalidResponse);
    var verifier = RekorVerifier.newRekorVerifier(rekorPub);

    var entry = response.getEntry();
    verifier.verifyEntry(entry);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyInclusionProof(entry));
    MatcherAssert.assertThat(
        thrown.getMessage(),
        CoreMatchers.startsWith(
            "Calculated inclusion proof root hash does not match provided root hash"));
  }
}
