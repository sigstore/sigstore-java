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

import com.google.protobuf.ByteString;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.rekor.client.ImmutableInclusionProof;
import dev.sigstore.rekor.client.ImmutableRekorEntry;
import dev.sigstore.rekor.client.ImmutableVerification;
import java.io.IOException;
import java.io.Reader;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;

class BundleReader {

  static Bundle readBundle(Reader jsonReader) throws BundleParseException {
    var protoBundleBuilder = dev.sigstore.proto.bundle.v1.Bundle.newBuilder();
    try {
      ProtoJson.parser().merge(jsonReader, protoBundleBuilder);
    } catch (IOException ioe) {
      throw new BundleParseException("Could not process bundle json", ioe);
    }

    var protoBundle = protoBundleBuilder.build();
    var bundleBuilder = ImmutableBundle.builder();
    if (!Bundle.SUPPORTED_MEDIA_TYPES.contains(protoBundle.getMediaType())) {
      throw new BundleParseException(
          "Unsupported bundle media type: " + protoBundle.getMediaType());
    }

    bundleBuilder.mediaType(protoBundle.getMediaType());

    if (protoBundle.getVerificationMaterial().getTlogEntriesCount() == 0) {
      throw new BundleParseException("Could not find any tlog entries in bundle json");
    }
    for (var bundleEntry : protoBundle.getVerificationMaterial().getTlogEntriesList()) {
      if (!bundleEntry.hasInclusionProof()) {
        // all consumed bundles must have an inclusion proof
        throw new BundleParseException("Could not find an inclusion proof");
      }
      var bundleInclusionProof = bundleEntry.getInclusionProof();

      var inclusionProof =
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

      var verificationBuilder = ImmutableVerification.builder().inclusionProof(inclusionProof);
      if (bundleEntry.hasInclusionPromise()
          && !bundleEntry.getInclusionPromise().getSignedEntryTimestamp().isEmpty()) {
        verificationBuilder.signedEntryTimestamp(
            Base64.getEncoder()
                .encodeToString(
                    bundleEntry.getInclusionPromise().getSignedEntryTimestamp().toByteArray()));
      }
      var verification = verificationBuilder.build();

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

      bundleBuilder.addEntries(rekorEntry);
    }

    if (protoBundle.hasDsseEnvelope()) {
      var dsseEnvelopeProto = protoBundle.getDsseEnvelope();
      var dsseEnvelopeBuilder =
          ImmutableDsseEnvelope.builder()
              .payload(dsseEnvelopeProto.getPayload().toByteArray())
              .payloadType(dsseEnvelopeProto.getPayloadType());
      for (int sigIndex = 0; sigIndex < dsseEnvelopeProto.getSignaturesCount(); sigIndex++) {
        dsseEnvelopeBuilder.addSignatures(
            ImmutableSignature.builder()
                .sig(dsseEnvelopeProto.getSignatures(sigIndex).getSig().toByteArray())
                .build());
      }
      bundleBuilder.dsseEnvelope(dsseEnvelopeBuilder.build());
    } else if (protoBundle.hasMessageSignature()) {
      var signature = protoBundle.getMessageSignature().getSignature().toByteArray();
      if (protoBundle.getMessageSignature().hasMessageDigest()) {
        var hashAlgorithm = protoBundle.getMessageSignature().getMessageDigest().getAlgorithm();
        if (hashAlgorithm != HashAlgorithm.SHA2_256) {
          throw new BundleParseException(
              "Cannot read message digests of type "
                  + hashAlgorithm
                  + ", only "
                  + HashAlgorithm.SHA2_256
                  + " is supported");
        }
        var messageSignature =
            ImmutableMessageSignature.builder()
                .messageDigest(
                    ImmutableMessageDigest.builder()
                        .hashAlgorithm(Bundle.HashAlgorithm.SHA2_256)
                        .digest(
                            protoBundle
                                .getMessageSignature()
                                .getMessageDigest()
                                .getDigest()
                                .toByteArray())
                        .build())
                .signature(signature)
                .build();
        bundleBuilder.messageSignature(messageSignature);
      } else {
        bundleBuilder.messageSignature(
            ImmutableMessageSignature.builder().signature(signature).build());
      }
    } else {
      throw new BundleParseException("A MessageSignature or DSSEEnvelope must be provided");
    }

    CertPath certPath;
    try {
      if (protoBundle.getVerificationMaterial().hasCertificate()) {
        certPath =
            ProtoMutators.toCertPath(
                List.of(protoBundle.getVerificationMaterial().getCertificate()));
      } else if (protoBundle.getVerificationMaterial().hasX509CertificateChain()) {
        certPath =
            ProtoMutators.toCertPath(
                protoBundle
                    .getVerificationMaterial()
                    .getX509CertificateChain()
                    .getCertificatesList());
      } else if (protoBundle.getVerificationMaterial().hasPublicKey()) {
        throw new BundleParseException("Plain public keys are not supported by this client");
      } else {
        throw new BundleParseException("Could not find a certificate or certificate chain");
      }
    } catch (CertificateException ce) {
      throw new BundleParseException("Could not parse bundle certificate chain", ce);
    }
    bundleBuilder.certPath(certPath);

    if (protoBundle.getVerificationMaterial().hasTimestampVerificationData()) {
      for (var timestamp :
          protoBundle
              .getVerificationMaterial()
              .getTimestampVerificationData()
              .getRfc3161TimestampsList()) {
        bundleBuilder.addTimestamps(
            ImmutableTimestamp.builder()
                .rfc3161Timestamp(timestamp.getSignedTimestamp().toByteArray())
                .build());
      }
    }

    return bundleBuilder.build();
  }
}
