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

import com.google.common.collect.Iterables;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.KeylessSignature;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.bundle.v1.Bundle;
import dev.sigstore.proto.bundle.v1.VerificationMaterial;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.proto.common.v1.HashOutput;
import dev.sigstore.proto.common.v1.LogId;
import dev.sigstore.proto.common.v1.MessageSignature;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v1.Checkpoint;
import dev.sigstore.proto.rekor.v1.InclusionPromise;
import dev.sigstore.proto.rekor.v1.InclusionProof;
import dev.sigstore.proto.rekor.v1.KindVersion;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.rekor.client.ImmutableInclusionProof;
import dev.sigstore.rekor.client.ImmutableRekorEntry;
import dev.sigstore.rekor.client.ImmutableVerification;
import dev.sigstore.rekor.client.RekorEntry;
import java.io.IOException;
import java.io.Reader;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;

/**
 * Generates Sigstore Bundle. Implementation note: the class is package-private to avoid exposing
 * the protobuf types in the public API.
 *
 * @see <a href="https://github.com/sigstore/protobuf-specs">Sigstore Bundle Protobuf
 *     specifications</a>
 */
class BundleFactoryInternal {
  static final JsonFormat.Printer JSON_PRINTER = JsonFormat.printer();

  private static final String BUNDLE_V_0_1 = "application/vnd.dev.sigstore.bundle+json;version=0.1";
  private static final String BUNDLE_V_0_2 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
  private static final String BUNDLE_V_0_3 = "application/vnd.dev.sigstore.bundle+json;version=0.3";
  private static final List<String> SUPPORTED_MEDIA_TYPES =
      List.of(BUNDLE_V_0_1, BUNDLE_V_0_2, BUNDLE_V_0_3);

  /**
   * Generates Sigstore Bundle Builder from {@link KeylessSignature}. This might be useful in case
   * you want to add additional information to the bundle.
   *
   * @param signingResult Keyless signing result.
   * @return Sigstore Bundle in protobuf builder format
   */
  static Bundle.Builder createBundleBuilder(KeylessSignature signingResult) {
    if (signingResult.getDigest().length == 0) {
      throw new IllegalStateException(
          "keyless signature must have artifact digest when serializing to bundle");
    }
    return Bundle.newBuilder()
        .setMediaType(BUNDLE_V_0_3)
        .setVerificationMaterial(buildVerificationMaterial(signingResult))
        .setMessageSignature(
            MessageSignature.newBuilder()
                .setMessageDigest(
                    HashOutput.newBuilder()
                        .setAlgorithm(HashAlgorithm.SHA2_256)
                        .setDigest(ByteString.copyFrom(signingResult.getDigest())))
                .setSignature(ByteString.copyFrom(signingResult.getSignature())));
  }

  private static VerificationMaterial.Builder buildVerificationMaterial(
      KeylessSignature signingResult) {
    X509Certificate cert;
    var javaCert = Iterables.getLast(signingResult.getCertPath().getCertificates());
    try {
      cert = ProtoMutators.fromCert((java.security.cert.X509Certificate) javaCert);
    } catch (CertificateEncodingException ce) {
      throw new IllegalArgumentException("Cannot encode certificate " + javaCert, ce);
    }
    var builder = VerificationMaterial.newBuilder().setCertificate(cert);
    if (signingResult.getEntry().isEmpty()) {
      throw new IllegalArgumentException("A log entry must be present in the signing result");
    }
    builder.addTlogEntries(buildTlogEntries(signingResult.getEntry().get()));
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

  static KeylessSignature readBundle(Reader jsonReader) throws BundleParseException {
    Bundle.Builder bundleBuilder = Bundle.newBuilder();
    try {
      JsonFormat.parser().merge(jsonReader, bundleBuilder);
    } catch (IOException ioe) {
      throw new BundleParseException("Could not process bundle json", ioe);
    }

    Bundle bundle = bundleBuilder.build();
    if (!SUPPORTED_MEDIA_TYPES.contains(bundle.getMediaType())) {
      throw new BundleParseException("Unsupported bundle media type: " + bundle.getMediaType());
    }

    if (bundle.getVerificationMaterial().getTlogEntriesCount() == 0) {
      throw new BundleParseException("Could not find any tlog entries in bundle json");
    }
    var bundleEntry = bundle.getVerificationMaterial().getTlogEntries(0);
    RekorEntry.InclusionProof inclusionProof = null;
    if (!bundleEntry.hasInclusionProof()) {
      // all consumed bundles must have an inclusion proof
      throw new BundleParseException("Could not find an inclusion proof");
    } else {
      var bundleInclusionProof = bundleEntry.getInclusionProof();

      inclusionProof =
          ImmutableInclusionProof.builder()
              .logIndex(bundleInclusionProof.getLogIndex())
              .rootHash(Hex.toHexString(bundleInclusionProof.getRootHash().toByteArray()))
              .treeSize(bundleInclusionProof.getTreeSize())
              .checkpoint(bundleInclusionProof.getCheckpoint().getEnvelope())
              .addAllHashes(
                  bundleInclusionProof.getHashesList().stream()
                      .map(ByteString::toByteArray)
                      .map(Hex::toHexString)
                      .collect(Collectors.toList()))
              .build();
    }

    var verification =
        ImmutableVerification.builder()
            .signedEntryTimestamp(
                Base64.getEncoder()
                    .encodeToString(
                        bundleEntry.getInclusionPromise().getSignedEntryTimestamp().toByteArray()))
            .inclusionProof(inclusionProof)
            .build();

    var rekorEntry =
        ImmutableRekorEntry.builder()
            .integratedTime(bundleEntry.getIntegratedTime())
            .logID(Hex.toHexString(bundleEntry.getLogId().getKeyId().toByteArray()))
            .logIndex(bundleEntry.getLogIndex())
            .body(
                Base64.getEncoder()
                    .encodeToString(bundleEntry.getCanonicalizedBody().toByteArray()))
            .verification(verification)
            .build();

    if (bundle.hasDsseEnvelope()) {
      throw new BundleParseException("DSSE envelope signatures are not supported by this client");
    }

    var digest = new byte[] {};
    if (bundle.getMessageSignature().hasMessageDigest()) {
      var hashAlgorithm = bundle.getMessageSignature().getMessageDigest().getAlgorithm();
      if (hashAlgorithm != HashAlgorithm.SHA2_256) {
        throw new BundleParseException(
            "Cannot read message digests of type "
                + hashAlgorithm
                + ", only "
                + HashAlgorithm.SHA2_256
                + " is supported");
      }
      digest = bundle.getMessageSignature().getMessageDigest().getDigest().toByteArray();
    }

    CertPath certPath;
    try {
      if (bundle.getVerificationMaterial().hasCertificate()) {
        certPath =
            ProtoMutators.toCertPath(List.of(bundle.getVerificationMaterial().getCertificate()));
      } else {
        certPath =
            ProtoMutators.toCertPath(
                bundle.getVerificationMaterial().getX509CertificateChain().getCertificatesList());
      }
    } catch (CertificateException ce) {
      throw new BundleParseException("Could not parse bundle certificate chain", ce);
    }
    return KeylessSignature.builder()
        .digest(digest)
        .certPath(certPath)
        .signature(bundle.getMessageSignature().getSignature().toByteArray())
        .entry(rekorEntry)
        .build();
  }
}
