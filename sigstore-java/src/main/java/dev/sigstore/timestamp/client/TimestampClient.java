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
package dev.sigstore.timestamp.client;

/** A client to communicate with a timestamp service instance. */
public interface TimestampClient {
  /**
   * Request a timestanp for a timestamp authority.
   *
   * @param tsReq a structured request for a timestamp
   * @return a {@link TimestampResponse} from the timestamp authority
   */
  TimestampResponse timestamp(TimestampRequest tsReq) throws TimestampException;
}
