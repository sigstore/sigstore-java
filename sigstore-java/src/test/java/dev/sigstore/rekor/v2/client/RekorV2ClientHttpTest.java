/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.rekor.v2.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.proto.common.v1.PublicKeyDetails;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.proto.rekor.v2.HashedRekordRequestV002;
import dev.sigstore.proto.rekor.v2.Signature;
import dev.sigstore.proto.rekor.v2.Verifier;
import dev.sigstore.testing.CertGenerator;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.UUID;
import org.bouncycastle.operator.OperatorCreationException;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorV2ClientHttpTest {
  private static RekorV2Client client;
  private static HashedRekordRequestV002 req;
  private static TransparencyLogEntry entry;

  @BeforeAll
  public static void setupClient() throws Exception {
    var service = Service.of(URI.create("https://log2025-alpha1.rekor.sigstage.dev/"), 2);
    client = RekorV2ClientHttp.builder().setService(service).build();
    req = createdRekorRequest();
    entry = client.putEntry(req);
  }

  @Test
  public void putEntry() throws Exception {
    var req = createdRekorRequest();
    var entry = client.putEntry(req);

    assertNotNull(entry);
    assertNotNull(entry.getInclusionProof());
    assertTrue(entry.getLogIndex() >= 0);
    assertNotNull(entry.getLogId());
  }

  @NotNull
  private static HashedRekordRequestV002 createdRekorRequest()
      throws NoSuchAlgorithmException,
          InvalidKeyException,
          SignatureException,
          OperatorCreationException,
          CertificateException,
          IOException {
    // the data we want to sign
    var data = "some data " + UUID.randomUUID();

    // get the digest
    var artifactDigest =
        MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));

    // sign the full content (these signers do the artifact hashing themselves)
    var signer = Signers.newEcdsaSigner();
    var signatureBytes = signer.sign(data.getBytes(StandardCharsets.UTF_8));

    // create a fake signing cert (not fulcio/dex)
    var cert = CertGenerator.newCert(signer.getPublicKey()).getEncoded();

    Verifier verifier =
        Verifier.newBuilder()
            .setX509Certificate(
                X509Certificate.newBuilder().setRawBytes(ByteString.copyFrom(cert)).build())
            .setKeyDetails(PublicKeyDetails.PKIX_ECDSA_P256_SHA_256)
            .build();

    Signature signature =
        Signature.newBuilder()
            .setContent(ByteString.copyFrom(signatureBytes))
            .setVerifier(verifier)
            .build();

    return HashedRekordRequestV002.newBuilder()
        .setDigest(ByteString.copyFrom(artifactDigest))
        .setSignature(signature)
        .build();
  }
}
