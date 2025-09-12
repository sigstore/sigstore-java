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
import com.google.protobuf.InvalidProtocolBufferException;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.proto.rekor.v2.DSSELogEntryV002;
import dev.sigstore.proto.rekor.v2.HashedRekordLogEntryV002;
import dev.sigstore.rekor.dsse.v0_0_1.Dsse;
import dev.sigstore.rekor.hashedRekord.v0_0_1.HashedRekord;

/** Parser for the body.spec element of {@link RekorEntry}. */
public class RekorTypes {

  /**
   * Parse a hashedrekord from rekor at api version 0.0.1.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed pojo
   * @throws RekorTypeException if the hashedrekord:0.0.1 entry could not be parsed
   */
  public static HashedRekord getHashedRekordV001(RekorEntry entry) throws RekorTypeException {
    expect(entry, "hashedrekord", "0.0.1");

    try {
      return GSON.get().fromJson(entry.getBodyDecoded().getSpec(), HashedRekord.class);
    } catch (JsonParseException jpe) {
      throw new RekorTypeException("Could not parse hashedrekord:0.0.1", jpe);
    }
  }

  /**
   * Parse a hashedrekord from rekor at api version 0.0.2.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed proto
   * @throws RekorTypeException if the hashedrekord:0.0.2 entry could not be parsed
   */
  public static HashedRekordLogEntryV002 getHashedRekordV002(RekorEntry entry)
      throws RekorTypeException {
    expect(entry, "hashedrekord", "0.0.2");

    try {
      HashedRekordLogEntryV002.Builder builder = HashedRekordLogEntryV002.newBuilder();
      ProtoJson.parser()
          .ignoringUnknownFields()
          .merge(
              GSON.get()
                  .toJson(
                      entry.getBodyDecoded().getSpec().getAsJsonObject().get("hashedRekordV002")),
              builder);
      return builder.build();
    } catch (InvalidProtocolBufferException
        | JsonParseException
        | NullPointerException
        | IllegalStateException e) {
      throw new RekorTypeException("Could not parse hashedrekord:0.0.2", e);
    }
  }

  /**
   * Parse a dsse from rekor at api version 0.0.1.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed pojo
   * @throws RekorTypeException if the dsse:0.0.1 entry could not be parsed
   */
  public static Dsse getDsseV001(RekorEntry entry) throws RekorTypeException {
    expect(entry, "dsse", "0.0.1");

    try {
      return GSON.get().fromJson(entry.getBodyDecoded().getSpec(), Dsse.class);
    } catch (JsonParseException jpe) {
      throw new RekorTypeException("Could not parse dsse:0.0.1", jpe);
    }
  }

  /**
   * Parse a dsse from rekor at api version 0.0.2.
   *
   * @param entry the rekor entry obtained from rekor
   * @return the parsed proto
   * @throws RekorTypeException if the dsse:0.0.2 entry could not be parsed
   */
  public static DSSELogEntryV002 getDsseV002(RekorEntry entry) throws RekorTypeException {
    expect(entry, "dsse", "0.0.2");

    try {
      DSSELogEntryV002.Builder builder = DSSELogEntryV002.newBuilder();
      ProtoJson.parser()
          .ignoringUnknownFields()
          .merge(
              GSON.get().toJson(entry.getBodyDecoded().getSpec().getAsJsonObject().get("dsseV002")),
              builder);
      return builder.build();
    } catch (InvalidProtocolBufferException
        | JsonParseException
        | NullPointerException
        | IllegalStateException e) {
      throw new RekorTypeException("Could not parse dsse:0.0.2", e);
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
