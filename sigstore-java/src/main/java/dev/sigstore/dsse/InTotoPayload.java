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
package dev.sigstore.dsse;

import static dev.sigstore.json.GsonSupplier.GSON;

import com.google.gson.JsonElement;
import dev.sigstore.bundle.Bundle.DsseEnvelope;
import dev.sigstore.json.JsonParseException;
import java.util.List;
import java.util.Map;
import org.immutables.gson.Gson;
import org.immutables.value.Value.Immutable;

@Gson.TypeAdapters
@Immutable
public interface InTotoPayload {

  String PAYLOAD_TYPE = "application/vnd.in-toto+json";

  @Gson.Named("_type")
  String getType();

  List<Subject> getSubject();

  String getPredicateType();

  /**
   * Predicate is not processed by this library, if you want to inspect the contents of an
   * attestation, you want to use an attestation parser.
   */
  JsonElement getPredicate();

  @Immutable
  interface Subject {

    String getName();

    Map<String, String> getDigest();
  }

  static InTotoPayload from(String payload) throws JsonParseException {
    return GSON.get().fromJson(payload, InTotoPayload.class);
  }

  static InTotoPayload from(DsseEnvelope dsseEnvelope) throws JsonParseException {
    return from(dsseEnvelope.getPayloadAsString());
  }
}
