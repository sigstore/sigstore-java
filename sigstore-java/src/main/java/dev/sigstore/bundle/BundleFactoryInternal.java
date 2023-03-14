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
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.ImmutableKeylessSignature;
import dev.sigstore.KeylessSignature;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.proto.bundle.v1.Bundle;
import dev.sigstore.proto.bundle.v1.VerificationMaterial;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.proto.common.v1.HashOutput;
import dev.sigstore.proto.common.v1.LogId;
import dev.sigstore.proto.common.v1.MessageSignature;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.common.v1.X509CertificateChain;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
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

  /**
   * Generates Sigstore Bundle Builder from {@link KeylessSignature}. This might be useful in case
   * you want to add additional information to the bundle.
   *
   * @param signingResult Keyless signing result.
   * @return Sigstore Bundle in protobuf builder format
   */
  static Bundle.Builder createBundleBuilder(KeylessSignature signingResult) {
    return Bundle.newBuilder()
        .setMediaType("application/vnd.dev.sigstore.bundle+json;version=0.1")
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
    return VerificationMaterial.newBuilder()
        .setX509CertificateChain(
            X509CertificateChain.newBuilder()
                .addAllCertificates(
                    signingResult.getCertPath().getCertificates().stream()
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
      throw new BundleParseException("Could not read bundle json", ioe);
    }
    Bundle bundle = bundleBuilder.build();

    var bundleEntry = bundle.getVerificationMaterial().getTlogEntries(0);
    var bundleInclusionProof = bundleEntry.getInclusionProof();

    ImmutableInclusionProof inclusionProof = null;
    if (bundleEntry.hasInclusionProof()) {
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
            .inclusionProof(Optional.ofNullable(inclusionProof))
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

    var hashAlgorithm = bundle.getMessageSignature().getMessageDigest().getAlgorithm();
    if (hashAlgorithm != HashAlgorithm.SHA2_256) {
      throw new BundleParseException(
          "Cannot read message digests of type "
              + hashAlgorithm
              + ", only "
              + HashAlgorithm.SHA2_256
              + " is supported");
    }
    try {
      return ImmutableKeylessSignature.builder()
          .digest(bundle.getMessageSignature().getMessageDigest().getDigest().toByteArray())
          .certPath(
              toCertPath(
                  bundle.getVerificationMaterial().getX509CertificateChain().getCertificatesList()))
          .signature(bundle.getMessageSignature().getSignature().toByteArray())
          .entry(rekorEntry)
          .build();
    } catch (CertificateException ce) {
      throw new BundleParseException("Could not parse bundle certificate chain", ce);
    }
  }

  private static CertPath toCertPath(List<X509Certificate> certificates)
      throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> converted = new ArrayList<>(certificates.size());
    for (var cert : certificates) {
      converted.add(Certificates.fromDer(cert.getRawBytes().toByteArray()));
    }
    return cf.generateCertPath(converted);
  }
}
