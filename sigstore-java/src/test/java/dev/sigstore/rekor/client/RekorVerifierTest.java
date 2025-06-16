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
import dev.sigstore.trustroot.ImmutableLogId;
import dev.sigstore.trustroot.ImmutablePublicKey;
import dev.sigstore.trustroot.ImmutableTransparencyLog;
import dev.sigstore.trustroot.ImmutableValidFor;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RekorVerifierTest {
  public String rekorResponse;
  public byte[] rekorPub;

  public static SigstoreTrustedRoot trustRoot;

  @BeforeEach
  public void loadResources() throws IOException {
    rekorResponse =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/entry.json"),
            StandardCharsets.UTF_8);
    rekorPub =
        Resources.toByteArray(
            Resources.getResource("dev/sigstore/samples/rekor-response/valid/rekor.pub"));
  }

  @BeforeAll
  public static void initTrustRoot() throws Exception {
    trustRoot =
        SigstoreTrustedRoot.from(
            Resources.getResource("dev/sigstore/trustroot/staging_trusted_root.json").openStream());
  }

  @Test
  public void verifyEntry_invalid() throws Exception {
    // change the logindex
    var invalidResponse = rekorResponse.replace("1688", "1700");
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), invalidResponse);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(response.getEntry()));
    Assertions.assertEquals("Entry SET was not valid", thrown.getMessage());
  }

  @Test
  public void verifyEntry() throws Exception {
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), rekorResponse);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var entry = response.getEntry();
    verifier.verifyEntry(entry);
  }

  @Test
  public void verifyEntry_withInvalidInclusionProof() throws Exception {
    // replace a hash in the inclusion proof to make it bad
    var invalidResponse = rekorResponse.replace("b4439e", "aaaaaa");

    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), invalidResponse);
    var verifier = RekorVerifier.newRekorVerifier(trustRoot);

    var entry = response.getEntry();
    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(entry));
    Assertions.assertEquals("Inclusion proof verification failed", thrown.getMessage());
  }

  @Test
  public void verifyEntry_logIdMismatch() throws Exception {
    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), rekorResponse);
    var tlog =
        ImmutableTransparencyLog.builder()
            .logId(
                ImmutableLogId.builder().keyId("garbage".getBytes(StandardCharsets.UTF_8)).build())
            .publicKey(
                ImmutablePublicKey.builder()
                    .validFor(ImmutableValidFor.builder().start(Instant.EPOCH).build())
                    .keyDetails("PKIX_ECDSA_P256_SHA_256")
                    .rawBytes(
                        Base64.decode(
                            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg=="))
                    .build())
            .hashAlgorithm("ignored")
            .baseUrl(URI.create("ignored"))
            .build();

    var verifier = RekorVerifier.newRekorVerifier(List.of(tlog));

    // make sure the entry time is valid for the log -- so we can determine the logid is the error
    // creator
    Assertions.assertTrue(
        tlog.getPublicKey()
            .getValidFor()
            .contains(Instant.ofEpochSecond(response.getEntry().getIntegratedTime())));

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(response.getEntry()));
    Assertions.assertEquals(
        "Log entry (logid, timestamp) does not match any provided transparency logs.",
        thrown.getMessage());
  }

  @Test
  public void verifyEntry_logIdTimeMismatch() throws Exception {

    var response = RekorResponse.newRekorResponse(new URI("https://somewhere"), rekorResponse);

    var tlog =
        ImmutableTransparencyLog.builder()
            .logId(
                ImmutableLogId.builder()
                    .keyId(Base64.decode("0y8wo8MtY5wrdiIFohx7sHeI5oKDpK5vQhGHI6G+pJY="))
                    .build())
            .publicKey(
                ImmutablePublicKey.builder()
                    .validFor(
                        ImmutableValidFor.builder()
                            .start(Instant.EPOCH)
                            .end(Instant.EPOCH.plus(1, ChronoUnit.SECONDS))
                            .build())
                    .keyDetails("PKIX_ECDSA_P256_SHA_256")
                    .rawBytes(
                        Base64.decode(
                            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg=="))
                    .build())
            .hashAlgorithm("ignored")
            .baseUrl(URI.create("ignored"))
            .build();

    var verifier = RekorVerifier.newRekorVerifier(List.of(tlog));

    // make sure logId is equal -- so we can determine the time is the error creator
    Assertions.assertArrayEquals(
        tlog.getLogId().getKeyId(), Hex.decode(response.getEntry().getLogID()));

    var thrown =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyEntry(response.getEntry()));
    Assertions.assertEquals(
        "Log entry (logid, timestamp) does not match any provided transparency logs.",
        thrown.getMessage());
  }
}
