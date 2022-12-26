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
package dev.sigstore.bundle;

import com.google.protobuf.ByteString;
import dev.sigstore.KeylessSigningResult;
import dev.sigstore.proto.bundle.v1.Bundle;
import dev.sigstore.proto.bundle.v1.VerificationMaterial;
import dev.sigstore.proto.common.v1.*;
import dev.sigstore.proto.rekor.v1.*;
import dev.sigstore.rekor.client.RekorEntry;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Generates Sigstore Bundle. Implementation note: the class is package-private to avoid exposing
 * the protobuf types in the public API.
 *
 * @see <a href="https://github.com/sigstore/protobuf-specs">Sigstore Bundle Protobuf
 *     specifications</a>
 */
class BundleFactoryInternal {
  /**
   * Generates Sigstore Bundle Builder from {@link KeylessSigningResult}. This might be useful in
   * case you want to add additional information to the bundle.
   *
   * @param signingResult Keyless signing result.
   * @return Sigstore Bundle in protobuf builder format
   */
  static Bundle.Builder createBundleBuilder(KeylessSigningResult signingResult) {
    return Bundle.newBuilder()
        .setMediaType("application/vnd.dev.sigstore.bundle+json;version=0.1")
        .setVerificationMaterial(buildVerificationMaterial(signingResult))
        .setMessageSignature(
            MessageSignature.newBuilder()
                .setMessageDigest(
                    HashOutput.newBuilder()
                        .setAlgorithm(HashAlgorithm.SHA2_256)
                        .setDigest(ByteString.fromHex(signingResult.getDigest()))));
  }

  private static VerificationMaterial.Builder buildVerificationMaterial(
      KeylessSigningResult signingResult) {
    return VerificationMaterial.newBuilder()
        .setX509CertificateChain(
            X509CertificateChain.newBuilder()
                .addAllCertificates(
                    signingResult
                        .getCertPath()
                        .getCertificates()
                        .stream()
                        .map(
                            c -> {
                              byte[] encoded;
                              try {
                                encoded = c.getEncoded();
                              } catch (CertificateEncodingException e) {
                                throw new IllegalArgumentException(
                                    "Cannot encode certificate " + c, e);
                              }
                              return X509Certificate.newBuilder()
                                  .setRawBytes(ByteString.copyFrom(encoded))
                                  .build();
                            })
                        .collect(Collectors.toList())))
        .addTlogEntries(buildTlogEntries(signingResult.getEntry()));
  }

  private static TransparencyLogEntry.Builder buildTlogEntries(RekorEntry entry) {
    TransparencyLogEntry.Builder transparencyLogEntry =
        TransparencyLogEntry.newBuilder()
            .setLogIndex(entry.getLogIndex())
            .setLogId(LogId.newBuilder().setKeyId(ByteString.fromHex(entry.getLogID())))
            .setKindVersion(
                KindVersion.newBuilder()
                    .setKind(entry.getBodyDecoded().getKind())
                    .setVersion(entry.getBodyDecoded().getApiVersion()))
            .setIntegratedTime(entry.getIntegratedTime())
            .setInclusionPromise(
                InclusionPromise.newBuilder()
                    .setSignedEntryTimestamp(
                        ByteString.copyFrom(
                            Base64.getDecoder()
                                .decode(entry.getVerification().getSignedEntryTimestamp()))))
            .setCanonicalizedBody(ByteString.copyFrom(Base64.getDecoder().decode(entry.getBody())));
    addInclusionProof(transparencyLogEntry, entry);
    return transparencyLogEntry;
  }

  private static void addInclusionProof(
      TransparencyLogEntry.Builder transparencyLogEntry, RekorEntry entry) {
    RekorEntry.InclusionProof inclusionProof =
        entry.getVerification().getInclusionProof().orElse(null);
    if (inclusionProof == null) {
      return;
    }
    transparencyLogEntry.setInclusionProof(
        InclusionProof.newBuilder()
            .setLogIndex(entry.getLogIndex())
            .setRootHash(ByteString.fromHex(inclusionProof.getRootHash()))
            .setTreeSize(inclusionProof.getTreeSize())
            .addAllHashes(
                inclusionProof
                    .getHashes()
                    .stream()
                    .map(ByteString::fromHex)
                    .collect(Collectors.toList()))
            .setCheckpoint(Checkpoint.newBuilder().setEnvelope(inclusionProof.getCheckpoint())));
  }
}
