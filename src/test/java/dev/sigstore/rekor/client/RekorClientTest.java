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

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.testing.CertGenerator;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.operator.OperatorCreationException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class RekorClientTest {

  private RekorClient client;

  @BeforeEach
  public void setupClient() throws URISyntaxException {
    // this tests directly against rekor in staging, it's a bit hard to bring up a rekor instance
    // without docker compose.
    client = RekorClient.builder().setServerUrl(new URI("https://rekor.sigstage.dev")).build();
  }

  @Test
  public void putEntry_toStaging() throws Exception {
    HashedRekordRequest req = createdRekorRequest();
    var resp = client.putEntry(req);

    // pretty basic testing
    MatcherAssert.assertThat(
        resp.getEntryLocation().toString(),
        CoreMatchers.startsWith("https://rekor.sigstage.dev/api/v1/log/entries/"));

    assertNotNull(resp.getUuid());
    assertNotNull(resp.getRaw());
    var entry = resp.getEntry();
    assertNotNull(entry.getBody());
    Assertions.assertTrue(entry.getIntegratedTime() > 1);
    assertNotNull(entry.getLogID());
    Assertions.assertTrue(entry.getLogIndex() > 0);
    assertNotNull(entry.getVerification().getSignedEntryTimestamp());
    //    Assertions.assertNotNull(entry.getVerification().getInclusionProof());
  }

  // TODO(patrick@chainguard.dev): don't use data from prod, create the data as part of the test
  // setup in staging.
  @Test
  public void searchEntries_nullParams() throws IOException {
    assertEquals(ImmutableList.of(), client.searchEntry(null, null, null, null));
  }

  @Test
  public void searchEntries_oneResult_hash() throws Exception {
    var newRekordRequest = createdRekorRequest();
    client.putEntry(newRekordRequest);
    assertEquals(
        1,
        client
            .searchEntry(
                null, newRekordRequest.getHashedRekord().getData().getHash().getValue(), null, null)
            .size());
  }

  @Test
  public void searchEntries_oneResult_publicKey() throws Exception {
    var newRekordRequest = createdRekorRequest();
    var resp = client.putEntry(newRekordRequest);
    assertEquals(
        1,
        client
            .searchEntry(
                null,
                null,
                "x509",
                RekorTypes.getHashedRekord(resp.getEntry())
                    .getSignature()
                    .getPublicKey()
                    .getContent())
            .size());
  }

  @Test
  public void searchEntries_moreThanOneResult_email()
      throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException,
          URISyntaxException, InvalidKeyException, OperatorCreationException {
    var newRekordRequest = createdRekorRequest();
    var newRekordRequest2 = createdRekorRequest();
    client.putEntry(newRekordRequest);
    client.putEntry(newRekordRequest2);
    assertTrue(
        client.searchEntry("test@test.com", null, null, null).size()
            > 1); // as long as our tests use staging this is just going to grow.
  }

  @Test
  public void searchEntries_zeroResults() throws IOException {
    assertTrue(
        client
            .searchEntry(
                null,
                "sha256:9f54fad117567ab4c2c6738beef765f7c362550534ffc0bfe8d96b0236d69661", // made
                // up sha
                null,
                null)
            .isEmpty());
  }

  @Test
  public void getEntry_entryExists() throws Exception {
    var newRekordRequest = createdRekorRequest();
    var resp = client.putEntry(newRekordRequest);
    var entry = client.getEntry(resp.getUuid());
    assertEntry(resp, entry);
  }

  @Test
  public void getEntry_hashedRekordRequest_byCalculatedUuid() throws Exception {
    var hashedRekordRequest = createdRekorRequest();
    var resp = client.putEntry(hashedRekordRequest);
    // getting an entry by hashedrekordrequest should implicitly calculate uuid
    // from the contents of the hashedrekord
    var entry = client.getEntry(hashedRekordRequest);
    assertEntry(resp, entry);
  }

  private void assertEntry(RekorResponse resp, Optional<RekorEntry> entry) {
    assertTrue(entry.isPresent());
    assertEquals(resp.getEntry().getLogID(), entry.get().getLogID());
    assertTrue(entry.get().getVerification().getInclusionProof().isPresent());
    assertNotNull(entry.get().getVerification().getInclusionProof().get().getTreeSize());
    assertNotNull(entry.get().getVerification().getInclusionProof().get().rootHash());
    assertNotNull(entry.get().getVerification().getInclusionProof().get().getLogIndex());
    assertTrue(entry.get().getVerification().getInclusionProof().get().getHashes().size() > 0);
  }

  @Test
  @Disabled("https://github.com/sigstore/sigstore-java/issues/62")
  public void getEntry_entryDoesntExist() throws IOException {
    Optional<RekorEntry> entry =
        client.getEntry(
            "aaaaaaaaaaaaaaaac8d2b213aa7efc1b2c9ccfa2fa647d00b34c63972e04e90276b5c31e0f317afd"); // I made this up
    assertTrue(entry.isEmpty());
  }

  @NotNull
  private HashedRekordRequest createdRekorRequest()
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
          OperatorCreationException, CertificateException, IOException {
    // the data we want to sign
    var data = "some data " + UUID.randomUUID();

    // get the digest
    var artifactDigest =
        MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));

    // sign the full content (these signers do the artifact hashing themselves)
    var signer = Signers.newEcdsaSigner();
    var signature = signer.sign(data.getBytes(StandardCharsets.UTF_8));

    // create a fake signing cert (not fulcio/dex)
    var cert = Certificates.toPemBytes(CertGenerator.newCert(signer.getPublicKey()));

    return HashedRekordRequest.newHashedRekordRequest(artifactDigest, cert, signature);
  }
}
