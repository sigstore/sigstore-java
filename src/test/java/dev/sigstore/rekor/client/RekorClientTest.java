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
import org.bouncycastle.operator.OperatorCreationException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
}
