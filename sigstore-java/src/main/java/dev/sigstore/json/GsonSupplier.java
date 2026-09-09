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
package dev.sigstore.json;

import com.google.gson.*;
import dev.sigstore.common.forbidden.SuppressForbidden;
import dev.sigstore.common.json.GsonByteArrayAdapter;
import dev.sigstore.common.json.GsonChecked;
import dev.sigstore.dsse.GsonAdaptersInTotoPayload;
import dev.sigstore.rekor.client.GsonAdaptersRekorEntry;
import dev.sigstore.rekor.client.GsonAdaptersRekorEntryBody;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.function.Supplier;

/**
 * Supplies a Gson with custom byte to base64 serialization, and no html escaping. This instance of
 * GSON is NOT html/url safe, but makes more sense if you want to do things for the serialization of
 * requests between sigstore and this client -- and should probably be used for any api call to
 * sigstore that expects JSON.
 */
@SuppressForbidden(reason = "GsonBuilder")
public enum GsonSupplier implements Supplier<GsonChecked> {
  GSON;

  @SuppressWarnings("ImmutableEnumChecker")
  private final GsonChecked gson =
      new GsonChecked(
          new GsonBuilder()
              .registerTypeAdapter(byte[].class, new GsonByteArrayAdapter())
              .registerTypeAdapter(
                  LocalDateTime.class,
                  (JsonDeserializer<LocalDateTime>)
                      (json, type, jsonDeserializationContext) ->
                          ZonedDateTime.parse(json.getAsJsonPrimitive().getAsString())
                              .toLocalDateTime())
              // Immutables generated GSON Adapters in alphabetical order
              .registerTypeAdapterFactory(new GsonAdaptersRekorEntry())
              .registerTypeAdapterFactory(new GsonAdaptersRekorEntryBody())
              .registerTypeAdapterFactory(new GsonAdaptersInTotoPayload())
              .disableHtmlEscaping()
              .create());

  @Override
  public GsonChecked get() {
    return gson;
  }
}
