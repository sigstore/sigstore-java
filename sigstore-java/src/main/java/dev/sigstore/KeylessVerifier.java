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
package dev.sigstore;

import com.google.api.client.util.Preconditions;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import com.google.gson.Gson;
import com.google.protobuf.InvalidProtocolBufferException;
import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.VerificationOptions.UncheckedCertificateException;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.Bundle.DsseEnvelope;
import dev.sigstore.bundle.Bundle.MessageSignature;
import dev.sigstore.dsse.InTotoPayload;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Verifiers;
import dev.sigstore.fulcio.client.FulcioVerificationException;
import dev.sigstore.fulcio.client.FulcioVerifier;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.proto.rekor.v2.DSSELogEntryV002;
import dev.sigstore.proto.rekor.v2.HashedRekordLogEntryV002;
import dev.sigstore.proto.rekor.v2.Signature;
import dev.sigstore.rekor.client.HashedRekordRequest;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorTypeException;
import dev.sigstore.rekor.client.RekorTypes;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.rekor.client.RekorVerifier;
import dev.sigstore.rekor.dsse.v0_0_1.Dsse;
import dev.sigstore.rekor.dsse.v0_0_1.PayloadHash;
import dev.sigstore.timestamp.client.ImmutableTimestampResponse;
import dev.sigstore.timestamp.client.TimestampException;
import dev.sigstore.timestamp.client.TimestampVerificationException;
import dev.sigstore.timestamp.client.TimestampVerifier;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

/** Verify hashrekords from rekor signed using the keyless signing flow with fulcio certificates. */
public class KeylessVerifier {

  private final FulcioVerifier fulcioVerifier;
  private final RekorVerifier rekorVerifier;
  private final TimestampVerifier timestampVerifier;

  private KeylessVerifier(
      FulcioVerifier fulcioVerifier,
      RekorVerifier rekorVerifier,
      TimestampVerifier timestampVerifier) {
    this.fulcioVerifier = fulcioVerifier;
    this.rekorVerifier = rekorVerifier;
    this.timestampVerifier = timestampVerifier;
  }

  public static KeylessVerifier.Builder builder() {
    return new KeylessVerifier.Builder();
  }

  public static class Builder {

    private TrustedRootProvider trustedRootProvider;

    public KeylessVerifier build()
        throws InvalidAlgorithmParameterException,
            CertificateException,
            InvalidKeySpecException,
            NoSuchAlgorithmException,
            SigstoreConfigurationException {
      Preconditions.checkNotNull(trustedRootProvider);
      var trustedRoot = trustedRootProvider.get();
      var fulcioVerifier = FulcioVerifier.newFulcioVerifier(trustedRoot);
      var rekorVerifier = RekorVerifier.newRekorVerifier(trustedRoot);
      var timestampVerifier = TimestampVerifier.newTimestampVerifier(trustedRoot);
      return new KeylessVerifier(fulcioVerifier, rekorVerifier, timestampVerifier);
    }

    public Builder sigstorePublicDefaults() {
      var sigstoreTufClientBuilder = SigstoreTufClient.builder().usePublicGoodInstance();
      trustedRootProvider = TrustedRootProvider.from(sigstoreTufClientBuilder);
      return this;
    }

    public Builder sigstoreStagingDefaults() {
      var sigstoreTufClientBuilder = SigstoreTufClient.builder().useStagingInstance();
      trustedRootProvider = TrustedRootProvider.from(sigstoreTufClientBuilder);
      return this;
    }

    public Builder trustedRootProvider(TrustedRootProvider trustedRootProvider) {
      this.trustedRootProvider = trustedRootProvider;
      return this;
    }
  }

  /** Convenience wrapper around {@link #verify(byte[], Bundle, VerificationOptions)}. */
  public void verify(Path artifact, Bundle bundle, VerificationOptions options)
      throws KeylessVerificationException {
    try {
      byte[] artifactDigest =
          Files.asByteSource(artifact.toFile()).hash(Hashing.sha256()).asBytes();
      verify(artifactDigest, bundle, options);
    } catch (IOException e) {
      throw new KeylessVerificationException("Could not hash provided artifact path: " + artifact);
    }
  }

  /**
   * Verify that the inputs can attest to the validity of a signature using sigstore's keyless
   * infrastructure. If no exception is thrown, it should be assumed verification has passed.
   *
   * @param artifactDigest the sha256 digest of the artifact that is being verified
   * @param bundle the sigstore signature bundle to verify
   * @param options the keyless verification data and options
   * @throws KeylessVerificationException if the signing information could not be verified
   */
  public void verify(byte[] artifactDigest, Bundle bundle, VerificationOptions options)
      throws KeylessVerificationException {

    if (bundle.getDsseEnvelope().isEmpty() && bundle.getMessageSignature().isEmpty()) {
      throw new IllegalStateException(
          "Bundle must contain a message signature or DSSE envelope to verify");
    }

    var signingCert = bundle.getCertPath();
    var leafCert = Certificates.getLeaf(signingCert);

    // a trusted CT log
    try {
      fulcioVerifier.verifySigningCertificate(signingCert);
    } catch (FulcioVerificationException | IOException ex) {
      throw new KeylessVerificationException(
          "Fulcio certificate was not valid: " + ex.getMessage(), ex);
    }

    // verify the certificate identity if options are present
    checkCertificateMatchers(leafCert, options.getCertificateMatchers());

    var rekorEntry = bundle.getEntries().get(0);

    byte[] signature;
    if (bundle.getMessageSignature().isPresent()) { // hashedrekord
      var messageSignature = bundle.getMessageSignature().get();
      checkMessageSignature(messageSignature, rekorEntry, artifactDigest, leafCert);
      signature = messageSignature.getSignature();
    } else { // dsse
      var dsseEnvelope = bundle.getDsseEnvelope().get();
      checkDsseEnvelope(rekorEntry, dsseEnvelope, artifactDigest, leafCert);
      signature = dsseEnvelope.getSignature();
    }

    verifyTimestamps(leafCert, bundle.getTimestamps(), signature);

    try {
      rekorVerifier.verifyEntry(rekorEntry);
    } catch (RekorVerificationException ex) {
      throw new KeylessVerificationException("Transparency log entry could not be verified", ex);
    }
  }

  private void verifyTimestamps(
      X509Certificate leafCert, List<Bundle.Timestamp> timestamps, byte[] signature)
      throws KeylessVerificationException {
    if (timestamps == null || timestamps.isEmpty()) {
      return;
    }
    for (Bundle.Timestamp timestamp : timestamps) {
      byte[] tsBytes = timestamp.getRfc3161Timestamp();
      if (tsBytes == null || tsBytes.length == 0) {
        throw new KeylessVerificationException(
            "Found an empty or null RFC3161 timestamp in bundle");
      }
      try {
        var tsResp = ImmutableTimestampResponse.builder().encoded(tsBytes).build();
        timestampVerifier.verify(tsResp, signature);
        leafCert.checkValidity(tsResp.getGenTime());
      } catch (TimestampException
          | CertificateNotYetValidException
          | CertificateExpiredException
          | TimestampVerificationException e) {
        throw new KeylessVerificationException(
            "RFC3161 timestamp verification failed: " + e.getMessage(), e);
      }
    }
  }

  @VisibleForTesting
  void checkCertificateMatchers(X509Certificate cert, List<CertificateMatcher> matchers)
      throws KeylessVerificationException {
    try {
      if (matchers.size() > 0 && matchers.stream().noneMatch(matcher -> matcher.test(cert))) {
        var matcherSpec =
            matchers.stream().map(Object::toString).collect(Collectors.joining(",", "[", "]"));
        throw new KeylessVerificationException(
            "No provided certificate identities matched values in certificate: " + matcherSpec);
      }
    } catch (UncheckedCertificateException ce) {
      throw new KeylessVerificationException(
          "Could not verify certificate identities: " + ce.getMessage());
    }
  }

  private void checkMessageSignature(
      MessageSignature messageSignature,
      RekorEntry rekorEntry,
      byte[] artifactDigest,
      X509Certificate leafCert)
      throws KeylessVerificationException {
    // this ensures the provided artifact digest matches what may have come from a bundle (in
    // keyless signature)
    if (messageSignature.getMessageDigest().isPresent()) {
      var bundleDigest = messageSignature.getMessageDigest().get().getDigest();
      if (!Arrays.equals(artifactDigest, bundleDigest)) {
        throw new KeylessVerificationException(
            "Provided artifact digest does not match digest used for verification"
                + "\nprovided(hex) : "
                + Hex.toHexString(artifactDigest)
                + "\nverification(hex) : "
                + Hex.toHexString(bundleDigest));
      }
    }

    // verify the signature over the artifact
    var signature = messageSignature.getSignature();
    try {
      if (!Verifiers.newVerifier(leafCert.getPublicKey()).verifyDigest(artifactDigest, signature)) {
        throw new KeylessVerificationException("Artifact signature was not valid");
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new RuntimeException(ex);
    } catch (SignatureException ex) {
      throw new KeylessVerificationException(
          "Signature could not be processed: " + ex.getMessage(), ex);
    }

    // recreate the log entry and check if it matches what was provided in the entry
    String version = rekorEntry.getBodyDecoded().getApiVersion();
    if ("0.0.1".equals(version)) {
      try {
        RekorTypes.getHashedRekord(rekorEntry);
        var calculatedHashedRekord =
            HashedRekordRequest.newHashedRekordRequest(
                    artifactDigest, Certificates.toPemBytes(leafCert), signature)
                .toJsonPayload();
        var body =
            new String(Base64.getDecoder().decode(rekorEntry.getBody()), StandardCharsets.UTF_8);
        if (!Objects.equals(calculatedHashedRekord, body)) {
          throw new KeylessVerificationException(
              "Provided verification materials are inconsistent with log entry");
        }
      } catch (IOException e) {
        // this should be unreachable, we know leafCert is a valid certificate at this point
        throw new RuntimeException("Unexpected IOException on valid leafCert", e);
      } catch (RekorTypeException re) {
        throw new KeylessVerificationException("Unexpected rekor type", re);
      }
    } else if ("0.0.2".equals(version)) {
      HashedRekordLogEntryV002 logEntrySpec;
      try {
        HashedRekordLogEntryV002.Builder builder = HashedRekordLogEntryV002.newBuilder();
        ProtoJson.parser()
            .ignoringUnknownFields()
            .merge(
                new Gson()
                    .toJson(
                        rekorEntry
                            .getBodyDecoded()
                            .getSpec()
                            .getAsJsonObject()
                            .get("hashedRekordV002")),
                builder);
        logEntrySpec = builder.build();
      } catch (InvalidProtocolBufferException ipbe) {
        throw new KeylessVerificationException("Could not parse hashedrekord from log entry body");
      }

      if (!logEntrySpec.getData().getAlgorithm().equals(HashAlgorithm.SHA2_256)) {
        throw new KeylessVerificationException(
            "Unsupported digest algorithm in log entry: " + logEntrySpec.getData().getAlgorithm());
      }

      if (!Arrays.equals(logEntrySpec.getData().getDigest().toByteArray(), artifactDigest)) {
        throw new KeylessVerificationException(
            "Artifact digest does not match digest in log entry spec");
      }

      if (!Arrays.equals(logEntrySpec.getSignature().getContent().toByteArray(), signature)) {
        throw new KeylessVerificationException(
            "Signature does not match signature in log entry spec");
      }

      var verifier = logEntrySpec.getSignature().getVerifier();
      if (!verifier.hasX509Certificate()) {
        throw new KeylessVerificationException("Rekor entry verifier is missing X.509 certificate");
      }
      try {
        byte[] certFromRekor = verifier.getX509Certificate().getRawBytes().toByteArray();
        byte[] certFromBundle = leafCert.getEncoded();
        if (!Arrays.equals(certFromRekor, certFromBundle)) {
          throw new KeylessVerificationException(
              "Certificate in rekor entry does not match certificate in bundle");
        }
      } catch (CertificateEncodingException e) {
        throw new KeylessVerificationException(
            "Could not encode leaf certificate for comparison", e);
      }
    } else {
      throw new KeylessVerificationException("Unsupported hashedrekord version: " + version);
    }
  }

  private void checkDsseEnvelope(
      RekorEntry rekorEntry,
      DsseEnvelope dsseEnvelope,
      byte[] artifactDigest,
      X509Certificate leafCert)
      throws KeylessVerificationException {
    // verify the artifact is in the subject list of the envelope
    if (!Objects.equals(InTotoPayload.PAYLOAD_TYPE, dsseEnvelope.getPayloadType())) {
      throw new KeylessVerificationException(
          "DSSE envelope must have payload type "
              + InTotoPayload.PAYLOAD_TYPE
              + ", but found '"
              + dsseEnvelope.getPayloadType()
              + "'");
    }
    InTotoPayload payload = InTotoPayload.from(dsseEnvelope);

    // find one sha256 hash in the subject list that matches the artifact hash
    if (payload.getSubject().stream()
        .noneMatch(
            subject -> {
              if (subject.getDigest().containsKey("sha256")) {
                try {
                  var digestBytes = Hex.decode(subject.getDigest().get("sha256"));
                  return Arrays.equals(artifactDigest, digestBytes);
                } catch (DecoderException de) {
                  // ignore (assume false)
                }
              }
              return false;
            })) {
      var providedHashes =
          payload.getSubject().stream()
              .map(s -> s.getDigest().getOrDefault("sha256", "no-sha256-hash"))
              .collect(Collectors.joining(",", "[", "]"));

      throw new KeylessVerificationException(
          "Provided artifact digest does not match any subject sha256 digests in DSSE payload"
              + "\nprovided(hex) : "
              + Hex.toHexString(artifactDigest)
              + "\nverification  : "
              + providedHashes);
    }

    // verify the dsse signature
    if (dsseEnvelope.getSignatures().size() != 1) {
      throw new KeylessVerificationException(
          "DSSE envelope must have exactly 1 signature, but found: "
              + dsseEnvelope.getSignatures().size());
    }
    try {
      if (!Verifiers.newVerifier(leafCert.getPublicKey())
          .verify(dsseEnvelope.getPAE(), dsseEnvelope.getSignature())) {
        throw new KeylessVerificationException("DSSE signature was not valid");
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new RuntimeException(ex);
    } catch (SignatureException se) {
      throw new KeylessVerificationException("Signature could not be processed", se);
    }

    String version = rekorEntry.getBodyDecoded().getApiVersion();
    if ("0.0.1".equals(version)) {
      Dsse rekorDsse;
      try {
        rekorDsse = RekorTypes.getDsse(rekorEntry);
      } catch (RekorTypeException re) {
        throw new KeylessVerificationException("Unexpected rekor type", re);
      }

      var algorithm = rekorDsse.getPayloadHash().getAlgorithm();
      if (algorithm != PayloadHash.Algorithm.SHA_256) {
        throw new KeylessVerificationException(
            "Cannot process DSSE entry with hashing algorithm " + algorithm.toString());
      }

      // check if the digest over the dsse payload matches the digest in the transparency log entry
      byte[] payloadDigest;
      try {
        payloadDigest = Hex.decode(rekorDsse.getPayloadHash().getValue());
      } catch (DecoderException de) {
        throw new KeylessVerificationException(
            "Could not decode hex sha256 artifact hash in hashrekord", de);
      }

      byte[] calculatedDigest = Hashing.sha256().hashBytes(dsseEnvelope.getPayload()).asBytes();
      if (!Arrays.equals(calculatedDigest, payloadDigest)) {
        throw new KeylessVerificationException(
            "Digest of DSSE payload in bundle does not match DSSE payload digest in log entry");
      }

      // check if the signature over the dsse payload matches the signature in the rekorEntry
      if (rekorDsse.getSignatures().size() != 1) {
        throw new KeylessVerificationException(
            "DSSE log entry must have exactly 1 signature, but found: "
                + rekorDsse.getSignatures().size());
      }

      if (!Base64.getEncoder()
          .encodeToString(dsseEnvelope.getSignature())
          .equals(rekorDsse.getSignatures().get(0).getSignature())) {
        throw new KeylessVerificationException(
            "Provided DSSE signature materials are inconsistent with DSSE log entry");
      }
    } else if ("0.0.2".equals(version)) {
      DSSELogEntryV002 logEntrySpec;
      try {
        DSSELogEntryV002.Builder builder = DSSELogEntryV002.newBuilder();
        ProtoJson.parser()
            .merge(
                new Gson()
                    .toJson(
                        rekorEntry.getBodyDecoded().getSpec().getAsJsonObject().get("dsseV002")),
                builder);
        logEntrySpec = builder.build();
      } catch (InvalidProtocolBufferException ipbe) {
        throw new KeylessVerificationException("Could not parse DSSE from log entry body", ipbe);
      }

      if (!logEntrySpec.getPayloadHash().getAlgorithm().equals(HashAlgorithm.SHA2_256)) {
        throw new KeylessVerificationException(
            "Unsupported digest algorithm in log entry: "
                + logEntrySpec.getPayloadHash().getAlgorithm());
      }

      // check if the digest over the dsse payload matches the digest in the transparency log entry
      byte[] calculatedDigest = Hashing.sha256().hashBytes(dsseEnvelope.getPayload()).asBytes();
      if (!Arrays.equals(
          logEntrySpec.getPayloadHash().getDigest().toByteArray(), calculatedDigest)) {
        throw new KeylessVerificationException(
            "Digest of DSSE payload in bundle does not match DSSE payload digest in log entry");
      }

      // check if the signature over the dsse payload matches the signature in the rekorEntry
      if (logEntrySpec.getSignaturesCount() != 1) {
        throw new KeylessVerificationException(
            "Log entry spec must have exactly 1 signature, but found: "
                + logEntrySpec.getSignaturesCount());
      }

      Signature logSignature = logEntrySpec.getSignatures(0);
      if (!Arrays.equals(dsseEnvelope.getSignature(), logSignature.getContent().toByteArray())) {
        throw new KeylessVerificationException(
            "Signature in DSSE envelope does not match signature in log entry spec");
      }

      var verifier = logSignature.getVerifier();
      if (!verifier.hasX509Certificate()) {
        throw new KeylessVerificationException(
            "Rekor entry DSSE verifier is missing X.509 certificate");
      }
      try {
        byte[] certFromRekor = verifier.getX509Certificate().getRawBytes().toByteArray();
        byte[] certFromBundle = leafCert.getEncoded();
        if (!Arrays.equals(certFromRekor, certFromBundle)) {
          throw new KeylessVerificationException(
              "Certificate in rekor entry does not match certificate in bundle");
        }
      } catch (CertificateEncodingException e) {
        throw new KeylessVerificationException(
            "Could not encode leaf certificate for comparison", e);
      }
    } else {
      throw new KeylessVerificationException("Unsupported DSSE version: " + version);
    }
  }
}
