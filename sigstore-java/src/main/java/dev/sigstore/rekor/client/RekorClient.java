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

import dev.sigstore.json.JsonParseException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

/** A client to communicate with a rekor service instance. */
public interface RekorClient {
  /**
   * Put a new hashedrekord entry on the Rekor log.
   *
   * @param hashedRekordRequest the request to send to rekor
   * @return a {@link RekorResponse} with information about the log entry
   */
  RekorResponse putEntry(HashedRekordRequest hashedRekordRequest)
      throws IOException, RekorParseException;

  /**
   * Get an entry from the log
   *
   * @param hashedRekordRequest the entry to find
   * @return the entry if found on the log, empty otherwise
   */
  Optional<RekorEntry> getEntry(HashedRekordRequest hashedRekordRequest)
      throws IOException, RekorParseException;

  /**
   * Get an entry from the log
   *
   * @param UUID the uuid of the log entry
   * @return the entry if found on the log, empty otherwise
   */
  Optional<RekorEntry> getEntry(String UUID) throws IOException, RekorParseException;

  /**
   * Returns a list of UUIDs for matching entries for the given search parameters.
   *
   * @param email the OIDC email subject
   * @param hash sha256 hash of the artifact
   * @param publicKeyFormat format of public key (one of 'pgp','x509','minisign', 'ssh', 'tuf')
   * @param publicKeyContent public key base64 encoded content
   */
  List<String> searchEntry(
      String email, String hash, String publicKeyFormat, String publicKeyContent)
      throws IOException, JsonParseException;
}
