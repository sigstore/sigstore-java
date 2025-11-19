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
package dev.sigstore.rekor.client;

import static dev.sigstore.json.GsonSupplier.GSON;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.protobuf.InvalidProtocolBufferException;
import dev.sigstore.json.JsonParseException;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.ProtoMutators;
import dev.sigstore.proto.rekor.v1.TransparencyLogEntry;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import javax.annotation.Nullable;
import org.erdtman.jcs.JsonCanonicalizer;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;
import org.immutables.value.Value.Lazy;

/** A local representation of a rekor entry in the log. */
@Gson.TypeAdapters
@Value.Immutable
public interface RekorEntry {

  /** A class representing verification information for a log entry. */
  @Value.Immutable
  interface Verification {
    /** Return the signed entry timestamp. */
    @Nullable
    String getSignedEntryTimestamp();

    /** Return the inclusion proof. */
    @Nullable
    InclusionProof getInclusionProof();
  }

  /**
   * Inclusion proof to allow verification that the entry is truly part of the Rekor merkle tree.
   */
  @Value.Immutable
  interface InclusionProof {

    /**
     * A list of hashes required to compute the inclusion proof, sorted in order from leaf to root.
     *
     * @return list of SHA256 hash values expressed in hexadecimal format
     */
    List<String> getHashes();

    /** The index of the entry in the transparency log. */
    Long getLogIndex();

    /**
     * The hash value stored at the root of the merkle tree at the time the proof was generated.
     *
     * @return SHA256 hash value expressed in hexadecimal format
     */
    String getRootHash();

    /** The size of the merkle tree at the time the inclusion proof was generated. */
    Long getTreeSize();

    /** The checkpoint (signed tree head) that the inclusion proof is based on. */
    String getCheckpoint();

    /**
     * The checkpoint that {@link #getCheckpoint} provides, but parsed into component parts.
     *
     * @return a Checkpoint
     * @throws RekorParseException if the checkpoint is invalid
     */
    @Lazy
    default Checkpoint parsedCheckpoint() throws RekorParseException {
      return Checkpoints.from(getCheckpoint());
    }
  }

  @Value.Immutable
  interface Checkpoint {
    /** Signed portion of checkpoint. */
    String getSignedData();

    /** Unique identity for the log. */
    String getOrigin();

    /** Size of the log for this checkpoint. */
    Long getSize();

    /** Log root hash at the defined log size. */
    String getBase64Hash();

    /** A list of signatures associated with the checkpoint. */
    List<CheckpointSignature> getSignatures();
  }

  @Value.Immutable
  interface CheckpointSignature {
    /** Human readable log identity */
    String getIdentity();

    /** First 4 bytes of sha256 key hash as a Public Key hint. */
    byte[] getKeyHint();

    /** Signature over the tree head. */
    byte[] getSignature();
  }

  /** Returns the content of the log entry. */
  String getBody();

  /**
   * Returns a decoded {@link RekorEntryBody} of the log entry. Use {@link RekorTypes} to further
   * process.
   */
  @Lazy
  default RekorEntryBody getBodyDecoded() throws JsonParseException {
    return GSON.get()
        .fromJson(new String(Base64.getDecoder().decode(getBody()), UTF_8), RekorEntryBody.class);
  }

  /** Returns canonicalized json representing the signable contents of a rekor entry. */
  default byte[] getSignableContent() {
    var signableContent = new HashMap<String, Object>();
    signableContent.put("body", getBody());
    signableContent.put("integratedTime", getIntegratedTime());
    signableContent.put("logID", getLogID());
    signableContent.put("logIndex", getLogIndex());

    try {
      return new JsonCanonicalizer(GSON.get().toJson(signableContent)).getEncodedUTF8();
    } catch (IOException e) {
      throw new RuntimeException("GSON generated invalid json when serializing RekorEntry");
    }
  }

  /** Returns the time the entry was integrated into the log. */
  long getIntegratedTime();

  @Derived
  @Gson.Ignore
  default Instant getIntegratedTimeInstant() {
    return Instant.ofEpochSecond(getIntegratedTime());
  }

  /**
   * Returns the sha256 of the log's public key. Should be the same for all entries into this log.
   */
  String getLogID();

  /** Returns the index in the log of this entry. */
  long getLogIndex();

  /** Returns the verification material for this entry. */
  Verification getVerification();

  /** Returns a RekorEntry from the JSON representation of a TransparencyLogEntry */
  static RekorEntry fromTLogEntryJson(String json) throws RekorParseException {
    if (Objects.isNull(json)) {
      throw new RekorParseException("Cannot parse null Rekor response");
    }
    try {
      TransparencyLogEntry.Builder builder = TransparencyLogEntry.newBuilder();
      ProtoJson.parser().ignoringUnknownFields().merge(json, builder);
      return ProtoMutators.toRekorEntry(builder.build());
    } catch (InvalidProtocolBufferException
        | com.google.gson.JsonParseException
        | NullPointerException e) {
      throw new RekorParseException("Failed to parse Rekor response JSON", e);
    }
  }
}
