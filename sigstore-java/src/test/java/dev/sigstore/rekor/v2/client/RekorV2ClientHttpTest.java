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
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.bundle.ImmutableDsseEnvelope;
import dev.sigstore.bundle.ImmutableSignature;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.proto.common.v1.PublicKeyDetails;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v2.DSSERequestV002;
import dev.sigstore.proto.rekor.v2.HashedRekordRequestV002;
import dev.sigstore.proto.rekor.v2.Signature;
import dev.sigstore.proto.rekor.v2.Verifier;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.testing.CertGenerator;
import dev.sigstore.trustroot.Service;
import dev.sigstore.tuf.SigstoreTufClient;
import io.intoto.EnvelopeOuterClass;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.operator.OperatorCreationException;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorV2ClientHttpTest {
  private static RekorV2Client client;
  private static HashedRekordRequestV002 req;
  private static RekorEntry entry;

  @BeforeAll
  public static void setupClient() throws Exception {
    var tufClient = SigstoreTufClient.builder().useStagingInstance().build();
    tufClient.update();
    var signingConfig = tufClient.getSigstoreSigningConfig();
    var rekorService = Service.select(signingConfig.getTLogs(), List.of(2)).get();

    client = RekorV2ClientHttp.builder().setService(rekorService).build();
    req = createdRekorRequest();
    entry = client.putEntry(req);
  }

  @Test
  public void putEntry() throws Exception {
    var req = createdRekorRequest();
    var entry = client.putEntry(req);

    assertNotNull(entry);
    assertNotNull(entry.getVerification().getInclusionProof());
    assertTrue(entry.getLogIndex() >= 0);
    assertNotNull(entry.getLogID());
  }

  @Test
  public void putEntry_dsse() throws Exception {
    var req = createDsseRequest();
    var entry = client.putEntry(req);

    assertNotNull(entry);
    assertNotNull(entry.getVerification().getInclusionProof());
    assertTrue(entry.getLogIndex() >= 0);
    assertNotNull(entry.getLogID());
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
    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);
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

  @NotNull
  private static DSSERequestV002 createDsseRequest()
      throws NoSuchAlgorithmException,
          InvalidKeyException,
          SignatureException,
          OperatorCreationException,
          CertificateException,
          IOException {
    var payload = "{\"foo\":\"bar\"}";
    var payloadType = "application/vnd.in-toto+json";

    // sign the full content (these signers do the artifact hashing themselves)
    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);

    // create a fake signing cert (not fulcio/dex)
    var cert = CertGenerator.newCert(signer.getPublicKey()).getEncoded();

    var dsse =
        ImmutableDsseEnvelope.builder()
            .payload(payload.getBytes(StandardCharsets.UTF_8))
            .payloadType(payloadType)
            .build();

    var pae = dsse.getPAE();
    var sig = signer.sign(pae);
    var dsseSigned =
        ImmutableDsseEnvelope.builder()
            .from(dsse)
            .addSignatures(ImmutableSignature.builder().sig(sig).build())
            .build();

    Verifier verifier =
        Verifier.newBuilder()
            .setX509Certificate(
                X509Certificate.newBuilder().setRawBytes(ByteString.copyFrom(cert)).build())
            .setKeyDetails(PublicKeyDetails.PKIX_ECDSA_P256_SHA_256)
            .build();

    return DSSERequestV002.newBuilder()
        .setEnvelope(
            EnvelopeOuterClass.Envelope.newBuilder()
                .setPayload(ByteString.copyFrom(dsseSigned.getPayload()))
                .setPayloadType(dsseSigned.getPayloadType())
                .addSignatures(
                    EnvelopeOuterClass.Signature.newBuilder().setSig(ByteString.copyFrom(sig))))
        .addVerifiers(verifier)
        .build();
  }
}
