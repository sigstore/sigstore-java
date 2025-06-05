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

import java.io.IOException;
import java.util.Date;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.immutables.value.Value.Immutable;
import org.immutables.value.Value.Lazy;

@Immutable
public interface TimestampResponse {
  /** The ASN.1 encoded representation of the timestamp response. */
  byte[] getEncoded();

  @Lazy
  default Date getGenTime() throws TimestampException {
    try {
      var bcTsResp = new TimeStampResponse(getEncoded());
      return bcTsResp.getTimeStampToken().getTimeStampInfo().getGenTime();
    } catch (TSPException | IOException e) {
      throw new TimestampException("Failed to retrieve timestamp generation time", e);
    }
  }
}
