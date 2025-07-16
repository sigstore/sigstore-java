/*
 * Copyright 2023 The Sigstore Authors.
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
package dev.sigstore.proto;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.proto.common.v1.X509Certificate;
import dev.sigstore.proto.rekor.v1.InclusionProof;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import dev.sigstore.rekor.client.ImmutableInclusionProof;
import dev.sigstore.rekor.client.ImmutableRekorEntry;
import dev.sigstore.rekor.client.ImmutableVerification;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorParseException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;

public class ProtoMutators {

  public static CertPath toCertPath(List<X509Certificate> certificates)
      throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> converted = new ArrayList<>(certificates.size());
    for (var cert : certificates) {
      converted.add(Certificates.fromDer(cert.getRawBytes().toByteArray()));
    }
    return cf.generateCertPath(converted);
  }

  public static Instant toInstant(Timestamp timestamp) {
    return Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos());
  }

  public static X509Certificate fromCert(java.security.cert.X509Certificate certificate)
      throws CertificateEncodingException {
    byte[] encoded;
    encoded = certificate.getEncoded();
    return X509Certificate.newBuilder().setRawBytes(ByteString.copyFrom(encoded)).build();
  }

  public static HashAlgorithm from(Bundle.HashAlgorithm algorithm) {
    if (algorithm == Bundle.HashAlgorithm.SHA2_256) {
      return HashAlgorithm.SHA2_256;
    }
    throw new IllegalStateException("Unknown hash algorithm: " + algorithm);
  }

  public static RekorEntry toRekorEntry(TransparencyLogEntry tle) throws RekorParseException {
    ImmutableRekorEntry.Builder builder = ImmutableRekorEntry.builder();

    builder.logIndex(tle.getLogIndex());
    builder.logID(Hex.toHexString(tle.getLogId().getKeyId().toByteArray()));
    builder.integratedTime(tle.getIntegratedTime());

    // The body of a RekorEntry is Base64 encoded
    builder.body(Base64.getEncoder().encodeToString(tle.getCanonicalizedBody().toByteArray()));

    ImmutableVerification.Builder verificationBuilder = ImmutableVerification.builder();

    // Rekor v2 entries won't have an InclusionPromise/SET
    if (tle.hasInclusionPromise()
        && !tle.getInclusionPromise().getSignedEntryTimestamp().isEmpty()) {
      verificationBuilder.signedEntryTimestamp(
          Base64.getEncoder()
              .encodeToString(tle.getInclusionPromise().getSignedEntryTimestamp().toByteArray()));
    }

    if (tle.hasInclusionProof()) {
      InclusionProof ipProto = tle.getInclusionProof();
      ImmutableInclusionProof.Builder ipBuilder = ImmutableInclusionProof.builder();
      ipBuilder.logIndex(ipProto.getLogIndex());
      ipBuilder.rootHash(Hex.toHexString(ipProto.getRootHash().toByteArray()));
      ipBuilder.treeSize(ipProto.getTreeSize());
      ipBuilder.checkpoint(ipProto.getCheckpoint().getEnvelope());
      ipProto
          .getHashesList()
          .forEach(hash -> ipBuilder.addHashes(Hex.toHexString(hash.toByteArray())));
      verificationBuilder.inclusionProof(ipBuilder.build());
    }
    builder.verification(verificationBuilder.build());

    return builder.build();
  }
}
