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

import com.google.common.collect.ImmutableList;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.testing.CertGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RekorClientTest {

  @Test
  public void putEntry_toStaging()
      throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException,
          SignatureException, InvalidKeyException, URISyntaxException {
    // the data we want to sign
    var data = "some data";

    // get the digest
    var artifactDigest =
        MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));

    // sign the full content (these signers do the artifact hashing themselves)
    var signer = Signers.newEcdsaSigner();
    var signature = signer.sign(data.getBytes(StandardCharsets.UTF_8));

    // create a fake signing cert (not fulcio/dex)
    var cert = CertGenerator.newCert(signer.getPublicKey());

    var req = HashedRekordRequest.newHashedRekordRequest(artifactDigest, cert, signature);

    // this tests directly against rekor in staging, it's a bit hard to bring up a rekor instance
    // without docker compose.
    var client = RekorClient.builder().setServerUrl(new URI("https://rekor.sigstage.dev")).build();
    var resp = client.putEntry(req);

    // pretty basic testing
    MatcherAssert.assertThat(
        resp.getEntryLocation().toString(),
        CoreMatchers.startsWith("https://rekor.sigstage.dev/api/v1/log/entries/"));

    Assertions.assertNotNull(resp.getUuid());
    Assertions.assertNotNull(resp.getRaw());
    var entry = resp.getEntry();
    Assertions.assertNotNull(entry.getBody());
    Assertions.assertTrue(entry.getIntegratedTime() > 1);
    Assertions.assertNotNull(entry.getLogID());
    Assertions.assertTrue(entry.getLogIndex() > 0);
    Assertions.assertNotNull(entry.getVerification().getSignedEntryTimestamp());
  }

  // TODO(patrick@chainguard.dev): don't use data from prod, create the data as part of the test
  // setup in staging.
  @Test
  public void searchEntries_nullParams() throws IOException {
    var client = RekorClient.builder().build();
    assertEquals(ImmutableList.of(), client.searchEntry(null, null, null, null));
  }

  @Test
  public void searchEntries_oneResult_hash() throws IOException {
    var client = RekorClient.builder().build();
    assertEquals(
        List.of("d9d2b213aa7efc1b2c9ccfa2fa647d00b34c63972e04e90276b5c31e0f317afd"),
        client.searchEntry(
            null,
            "sha256:9f54fad117567ab4c2c6738ebf0765f7c362550534ffc0bfe8d96b0236d69661",
            null,
            null));
  }

  @Test
  public void searchEntries_oneResult_publicKey() throws IOException {
    var client = RekorClient.builder().build();
    assertEquals(
        List.of("d9d2b213aa7efc1b2c9ccfa2fa647d00b34c63972e04e90276b5c31e0f317afd"),
        client.searchEntry(
            null,
            null,
            "x509",
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvVENDQWllZ0F3SUJBZ0lVRk43WXJPREowRm8zUTA3dW9NaVpEMlNpTXZRd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd05qQXpNVE16T0RFMldoY05Nakl3TmpBek1UTTBPREUyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVzMTB2WFBsZWNHZkhXMGZ4TStjeGRHai9FSUFoQnNBRnJqTysKYnlpVjRsUU51WnNqOUp0NUx4Vk1aOUtUWUJiSU5uUzVGVWx6MFpqQ3E2b1M3M0J3N0tPQ0FVWXdnZ0ZDTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVPUTRrCk9PaDVkL0wxc0tTeGZLOUFTUXUvUTJVd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pBWURWUjBSQVFIL0JCb3dHSUVXY0dGMGNtbGphMEJqYUdGcGJtZDFZWEprTG1SbGRqQW9CZ29yQmdFRQpBWU8vTUFFQkJCcG5iMjluYkdVdGMybG5jM1J2Y21VdGNISnZaSFZqZEdsdmJqQ0JpZ1lLS3dZQkJBSFdlUUlFCkFnUjhCSG9BZUFCMkFBaGdrdkFvVXY5b1JkSFJheWVFbkVWbkdLd1dQY000MG0zbXZDSUdObTl5QUFBQmdTbkoKdnRJQUFBUURBRWN3UlFJaEFOeGhKTVhMV2JEU0VrLzFCU1JQclJjQzdHSVF2VHlINGRIUlNSTllORTBSQWlCdgp1QnRmTlJPdTVlSkl6MCtyQ09lNjd0b2J6dWFMQ1FESHVrWEtEZGI5ZERBS0JnZ3Foa2pPUFFRREF3Tm9BREJsCkFqRUE0MGR5MHVCMHdWK3AwZFJwZnNIVmd3REtxaVNWTFNBYk5jNWJSTk9ueEVtSWhXVDV2SW1YVDRMUnF6SWIKRSt3dkFqQnpuU2M2UlUrOGhkcUFpMkFCOStWcW9ZQXBiTGlSYjI4cVlGSFNYV2doMWtpQng1dWVFMXdXWnVhcgpRSEE4VFRNPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="));
  }

  @Test
  public void searchEntries_moreThanOneResult_email() throws IOException {
    var client = RekorClient.builder().build();
    assertTrue(client.searchEntry("patrick@chainguard.dev", null, null, null).size() > 1);
  }

  @Test
  public void searchEntries_zeroResults() throws IOException {
    var client = RekorClient.builder().build();
    assertTrue(
        client
            .searchEntry(
                null,
                "sha256:9f54fad117567ab4c2c6738beef765f7c362550534ffc0bfe8d96b0236d69661",
                null,
                null)
            .isEmpty());
  }

  @Test
  public void getEntry_entryExists() throws IOException {
    Optional<RekorEntry> entry =
        RekorClient.builder()
            .build()
            .getEntry("d9d2b213aa7efc1b2c9ccfa2fa647d00b34c63972e04e90276b5c31e0f317afd");
    assertTrue(entry.isPresent());
    assertEquals(
        entry.get().getLogID(), "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");
  }

  @Test
  public void getEntry_entryDoesntExist() throws IOException {
    Optional<RekorEntry> entry =
        RekorClient.builder()
            .build()
            .getEntry("c8d2b213aa7efc1b2c9ccfa2fa647d00b34c63972e04e90276b5c31e0f317afd");
    assertTrue(entry.isEmpty());
  }
}
