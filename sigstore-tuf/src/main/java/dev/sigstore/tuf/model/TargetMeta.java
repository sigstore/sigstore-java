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
package dev.sigstore.tuf.model;

import java.util.Map;
import java.util.Optional;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/**
 * Metadata about a TUF target. @see <a
 * href="https://theupdateframework.github.io/specification/latest/#targets">targets</a>
 */
@Gson.TypeAdapters
@Value.Immutable
public interface TargetMeta extends TufMeta {

  /** List of Delegated roles that can specify their own set of targets within a file space. */
  Optional<Delegations> getDelegations();

  /** Maps target name (e.g. 'fulcio.crt.pem') to {@code TargetData}. */
  Map<String, TargetData> getTargets();

  /** Data about the target. */
  @Value.Immutable
  interface TargetData {

    /** Custom application specific metadata about the target. */
    Optional<Custom> getCustom();

    /**
     * Hash values of the target metadata. One or both of sha256 or sha512 is required to be
     * present.
     */
    Hashes getHashes();

    /** Length in bytes of the metadata. */
    int getLength();

    @Value.Check
    default void check() {
      if (getHashes().getSha256() == null && getHashes().getSha512() == null) {
        throw new IllegalStateException(
            "No hashes (sha256 or sha512) found for target data: " + this);
      }
    }
  }

  /** Field to store use-case specific labels/data. */
  @Value.Immutable
  interface Custom {

    /** Sigstore metadata for this target. */
    @Gson.Named("sigstore")
    SigstoreMeta getSigstoreMeta();
  }

  /** Sigstore Metadata. */
  @Value.Immutable
  interface SigstoreMeta {

    /**
     * Current status of this target. Currently "Expired", and "Active" are the two statuses in use.
     */
    String getStatus();

    /**
     * The URI of the endpoint that the TUF distributed key maps to. For instance if {@link
     * #getUsage()} were 'Fulcio' the prod key would have 'https://fulcio.sigstore.dev" as the URI.
     * This mapping can be used by clients to determine the right target public key material for a
     * given Fulcio/Rekor/CTFE endpoint.
     */
    Optional<String> getUri();

    /**
     * Sigstore usage of this target. Ties the file to a specific part of the Sigstore stack. Valid
     * values are "Fulcio", "CTFE", "Rekor", and "unknown".
     */
    String getUsage();
  }
}
