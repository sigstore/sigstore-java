/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.rekor.v2.client;

import dev.sigstore.proto.rekor.v2.DSSERequestV002;
import dev.sigstore.proto.rekor.v2.HashedRekordRequestV002;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorParseException;
import java.io.IOException;

/** A client to communicate with a rekor v2 service instance. */
public interface RekorV2Client {
  /**
   * Put a new hashedrekord entry on the Rekor log.
   *
   * @param hashedRekordRequest the request to send to rekor
   * @return a {@link RekorEntry} with information about the log entry
   */
  RekorEntry putEntry(HashedRekordRequestV002 hashedRekordRequest)
      throws IOException, RekorParseException;

  /**
   * Put a new dsse entry on the Rekor log.
   *
   * @param dsseRequest the request to send to rekor
   * @return a {@link RekorEntry} with information about the log entry
   */
  RekorEntry putEntry(DSSERequestV002 dsseRequest) throws IOException, RekorParseException;
}
