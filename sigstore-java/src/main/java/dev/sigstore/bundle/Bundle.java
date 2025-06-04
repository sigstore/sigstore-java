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

import com.google.common.base.Preconditions;
import dev.sigstore.rekor.client.RekorEntry;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.util.List;
import java.util.Optional;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.immutables.value.Value.Default;
import org.immutables.value.Value.Derived;
import org.immutables.value.Value.Immutable;
import org.immutables.value.Value.Lazy;

/**
 * A representation of sigstore signing materials. See <a
 * href="https://github.com/sigstore/protobuf-specs">protobuf-specs</a>
 */
@Immutable
public abstract class Bundle {

  public enum HashAlgorithm {
    SHA2_256
  }

  static final String BUNDLE_V_0_1 = "application/vnd.dev.sigstore.bundle+json;version=0.1";
  static final String BUNDLE_V_0_2 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
  static final String BUNDLE_V_0_3 = "application/vnd.dev.sigstore.bundle+json;version=0.3";
  // media_type format switch: https://github.com/sigstore/protobuf-specs/pull/279
  static final String BUNDLE_V_0_3_1 = "application/vnd.dev.sigstore.bundle.v0.3+json";
  static final List<String> SUPPORTED_MEDIA_TYPES =
      List.of(BUNDLE_V_0_1, BUNDLE_V_0_2, BUNDLE_V_0_3, BUNDLE_V_0_3_1);

  /** The bundle version */
  @Default
  public String getMediaType() {
    return BUNDLE_V_0_3_1;
  }

  /** A signature represented as a signature and digest */
  public abstract Optional<MessageSignature> getMessageSignature();

  /** A DSSE envelope signature type that may contain an arbitrary payload */
  public abstract Optional<DsseEnvelope> getDsseEnvelope();

  @Value.Check
  protected void checkOnlyOneSignature() {
    Preconditions.checkState(
        (getDsseEnvelope().isEmpty() && getMessageSignature().isPresent())
            || (getDsseEnvelope().isPresent() && getMessageSignature().isEmpty()));
  }

  @Value.Check
  protected void checkAtLeastOneTimestamp() {
    for (var entry : getEntries()) {
      if (entry.getVerification().getSignedEntryTimestamp() != null) {
        return;
      }
    }
    if (getTimestamps().size() > 0) {
      return;
    }
    throw new IllegalStateException("No timestamp verification (set, timestamp) was provided");
  }

  /**
   * The partial certificate chain provided by fulcio for the public key and identity used to sign
   * the artifact, this should NOT contain the trusted root or any trusted intermediates. But users
   * of this object should understand that older signatures may include the full chain.
   */
  public abstract CertPath getCertPath();

  /**
   * The entry in the rekor transparency log (represented as a list for future compatibility, but
   * currently only allow for at most one entry.
   */
  public abstract List<RekorEntry> getEntries();

  /** A list of timestamps to verify the time of signing. Currently, allows rfc3161 timestamps. */
  public abstract List<Timestamp> getTimestamps();

  @Immutable
  public interface MessageSignature {

    /**
     * An optional message digest, this should not be used to verify signature validity. A digest
     * should be provided or computed by the system.
     */
    Optional<MessageDigest> getMessageDigest();

    /** Signature over an artifact. */
    byte[] getSignature();

    static MessageSignature of(HashAlgorithm algorithm, byte[] digest, byte[] signature) {
      return ImmutableMessageSignature.builder()
          .signature(signature)
          .messageDigest(
              ImmutableMessageDigest.builder().digest(digest).hashAlgorithm(algorithm).build())
          .build();
    }
  }

  @Immutable
  public interface MessageDigest {

    /** The algorithm used to compute the digest. */
    HashAlgorithm getHashAlgorithm();

    /**
     * The raw bytes of the digest computer using the hashing algorithm described by {@link
     * #getHashAlgorithm()}
     */
    byte[] getDigest();
  }

  @Immutable
  public interface DsseEnvelope {

    /** An arbitrary payload that does not need to be parsed to be validated */
    byte[] getPayload();

    /** Information on how to interpret the payload */
    String getPayloadType();

    /** DSSE specific signature */
    List<Signature> getSignatures();

    /**
     * The "Pre-Authentication Encoding" of this statement. The signature is generated over this
     * content.
     */
    @Gson.Ignore
    @Derived
    default byte[] getPAE() {
      return ("DSSEv1 "
              + getPayloadType().length()
              + " "
              + getPayloadType()
              + " "
              + getPayloadAsString().length()
              + " "
              + getPayloadAsString())
          .getBytes(StandardCharsets.UTF_8);
    }

    @Lazy
    @Gson.Ignore
    default String getPayloadAsString() {
      return new String(getPayload(), StandardCharsets.UTF_8);
    }

    @Lazy
    @Gson.Ignore
    default byte[] getSignature() {
      return getSignatures().get(0).getSig();
    }

    @Immutable
    interface Signature {
      byte[] getSig();
    }
  }

  @Immutable
  public interface Timestamp {

    /** Raw bytes of an rfc3161 timestamp */
    byte[] getRfc3161Timestamp();
  }

  /** Read a json formatted bundle. */
  public static Bundle from(Reader bundleJson) throws BundleParseException {
    return BundleReader.readBundle(bundleJson);
  }

  /** Read a json formatted bundle from a file. */
  public static Bundle from(Path file, Charset cs) throws BundleParseException, IOException {
    return BundleReader.readBundle(Files.newBufferedReader(file, cs));
  }

  @Lazy
  public String toJson() {
    return BundleWriter.writeBundle(this);
  }
}
