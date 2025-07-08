/*
 * Copyright 2024 The Sigstore Authors.
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

import com.google.common.collect.Iterables;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.bundle.v1.TimestampVerificationData;
import dev.sigstore.proto.bundle.v1.VerificationMaterial;
import dev.sigstore.proto.common.v1.HashOutput;
import dev.sigstore.proto.common.v1.LogId;
import dev.sigstore.proto.common.v1.MessageSignature;
import dev.sigstore.proto.common.v1.RFC3161SignedTimestamp;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v1.Checkpoint;
import dev.sigstore.proto.rekor.v1.InclusionPromise;
import dev.sigstore.proto.rekor.v1.InclusionProof;
import dev.sigstore.proto.rekor.v1.KindVersion;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.rekor.client.RekorEntry;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

class BundleWriter {
  static final JsonFormat.Printer JSON_PRINTER = JsonFormat.printer();

  /**
   * Generates Sigstore Bundle JSON from {@link Bundle}.
   *
   * @param signingResult Keyless signing result as a bundle.
   * @return Sigstore Bundle in JSON format
   */
  static String writeBundle(Bundle signingResult) {
    var bundle = createBundleBuilder(signingResult).build();
    try {
      String jsonBundle = JSON_PRINTER.print(bundle);
      List<String> missingFields = BundleVerifier.findMissingFields(bundle);
      // TODO(#1018): Update handling of integrated_time once it becomes an optional field
      // integrated_time is a required field in the Bundle spec
      missingFields.removeIf(f -> f.endsWith("integrated_time"));
      if (!missingFields.isEmpty()) {
        throw new IllegalStateException(
            "Some of the fields were not initialized: "
                + String.join(", ", missingFields)
                + "; bundle JSON: "
                + jsonBundle);
      }
      return jsonBundle;
    } catch (InvalidProtocolBufferException e) {
      throw new IllegalArgumentException(
          "Can't serialize signing result to Sigstore Bundle JSON", e);
    }
  }

  /**
   * Generates Sigstore Bundle Builder from {@link Bundle}. This might be useful in case you want to
   * add additional information to the bundle.
   *
   * @param bundle Keyless signing result.
   * @return Sigstore Bundle in protobuf builder format
   */
  static dev.sigstore.proto.bundle.v1.Bundle.Builder createBundleBuilder(Bundle bundle) {
    if (bundle.getMessageSignature().isEmpty()) {
      throw new IllegalStateException("can only serialize bundles with message signatures");
    }
    var messageSignature = bundle.getMessageSignature().get();
    if (messageSignature.getMessageDigest().isEmpty()) {
      throw new IllegalStateException(
          "keyless signature must have artifact digest when serializing to bundle");
    }
    return dev.sigstore.proto.bundle.v1.Bundle.newBuilder()
        .setMediaType(bundle.getMediaType())
        .setVerificationMaterial(buildVerificationMaterial(bundle))
        .setMessageSignature(
            MessageSignature.newBuilder()
                .setMessageDigest(
                    HashOutput.newBuilder()
                        .setAlgorithm(
                            ProtoMutators.from(
                                messageSignature.getMessageDigest().get().getHashAlgorithm()))
                        .setDigest(
                            ByteString.copyFrom(
                                messageSignature.getMessageDigest().get().getDigest())))
                .setSignature(ByteString.copyFrom(messageSignature.getSignature())));
  }

  private static VerificationMaterial.Builder buildVerificationMaterial(Bundle bundle) {
    X509Certificate cert;
    var javaCert = Iterables.getLast(bundle.getCertPath().getCertificates());
    try {
      cert = ProtoMutators.fromCert((java.security.cert.X509Certificate) javaCert);
    } catch (CertificateEncodingException ce) {
      throw new IllegalArgumentException("Cannot encode certificate " + javaCert, ce);
    }
    var builder = VerificationMaterial.newBuilder().setCertificate(cert);
    if (bundle.getEntries().size() != 1) {
      throw new IllegalArgumentException(
          "Exactly 1 rekor entry must be present in the signing result");
    }
    builder.addTlogEntries(buildTlogEntries(bundle.getEntries().get(0)));
    buildTimestampVerificationData(bundle.getTimestamps())
        .ifPresent(data -> builder.setTimestampVerificationData(data));
    return builder;
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
            .setCanonicalizedBody(ByteString.copyFrom(Base64.getDecoder().decode(entry.getBody())));
    if (entry.getVerification().getSignedEntryTimestamp() != null) {
      transparencyLogEntry.setInclusionPromise(
          InclusionPromise.newBuilder()
              .setSignedEntryTimestamp(
                  ByteString.copyFrom(
                      Base64.getDecoder()
                          .decode(entry.getVerification().getSignedEntryTimestamp()))));
    }
    addInclusionProof(transparencyLogEntry, entry);
    return transparencyLogEntry;
  }

  private static void addInclusionProof(
      TransparencyLogEntry.Builder transparencyLogEntry, RekorEntry entry) {
    RekorEntry.InclusionProof inclusionProof = entry.getVerification().getInclusionProof();
    transparencyLogEntry.setInclusionProof(
        InclusionProof.newBuilder()
            .setLogIndex(inclusionProof.getLogIndex())
            .setRootHash(ByteString.fromHex(inclusionProof.getRootHash()))
            .setTreeSize(inclusionProof.getTreeSize())
            .addAllHashes(
                inclusionProof.getHashes().stream()
                    .map(ByteString::fromHex)
                    .collect(Collectors.toList()))
            .setCheckpoint(Checkpoint.newBuilder().setEnvelope(inclusionProof.getCheckpoint())));
  }

  private static Optional<TimestampVerificationData> buildTimestampVerificationData(
      List<Bundle.Timestamp> bundleTimestamps) {
    if (bundleTimestamps == null || bundleTimestamps.isEmpty()) {
      return Optional.empty();
    }
    TimestampVerificationData.Builder tsvBuilder = TimestampVerificationData.newBuilder();
    for (Bundle.Timestamp ts : bundleTimestamps) {
      byte[] tsBytes = ts.getRfc3161Timestamp();
      if (tsBytes != null && tsBytes.length > 0) {
        tsvBuilder.addRfc3161Timestamps(
            RFC3161SignedTimestamp.newBuilder().setSignedTimestamp(ByteString.copyFrom(tsBytes)));
      }
    }
    if (tsvBuilder.getRfc3161TimestampsCount() > 0) {
      return Optional.of(tsvBuilder.build());
    }
    return Optional.empty();
  }
}
