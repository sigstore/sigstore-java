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

import com.google.gson.JsonParseException;
import dev.sigstore.rekor.dsse.v0_0_1.Dsse;
import dev.sigstore.rekor.hashedRekord.v0_0_1.HashedRekord;

/** Parser for the body.spec element of {@link RekorEntry}. */
public class RekorTypes {

  /**
   * Parse a hashedrekord from rekor at api version 0.0.1.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed pojo
   * @throws RekorTypeException if the hashrekord:0.0.1 entry could not be parsed
   */
  public static HashedRekord getHashedRekord(RekorEntry entry) throws RekorTypeException {
    expect(entry, "hashedrekord", "0.0.1");

    try {
      return GSON.get().fromJson(entry.getBodyDecoded().getSpec(), HashedRekord.class);
    } catch (JsonParseException jpe) {
      throw new RekorTypeException("Could not parse hashrekord:0.0.1", jpe);
    }
  }

  /**
   * Parse a dsse from rekor at api version 0.0.1.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed pojo
   * @throws RekorTypeException if the dsse:0.0.1 entry could not be parsed
   */
  public static Dsse getDsse(RekorEntry entry) throws RekorTypeException {
    expect(entry, "dsse", "0.0.1");

    try {
      return GSON.get().fromJson(entry.getBodyDecoded().getSpec(), Dsse.class);
    } catch (JsonParseException jpe) {
      throw new RekorTypeException("Could not parse dsse:0.0.1", jpe);
    }
  }

  private static void expect(RekorEntry entry, String expectedKind, String expectedApiVersion)
      throws RekorTypeException {
    var kind = entry.getBodyDecoded().getKind();
    var apiVersion = entry.getBodyDecoded().getApiVersion();
    if (!(kind.equals(expectedKind) && apiVersion.equals(expectedApiVersion))) {
      throw new RekorTypeException(
          "Expecting type "
              + expectedKind
              + ":"
              + expectedApiVersion
              + ", but found "
              + kind
              + ":"
              + apiVersion);
    }
  }
}
