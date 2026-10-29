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

import java.util.List;
import java.util.Map;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/** Information about a key that has been used to sign some TUF content. */
@Gson.TypeAdapters
@Value.Immutable
public interface Key {

  /** List of has algorithms this key has been signed with. */
  @Gson.Named("keyid_hash_algorithms")
  List<String> getKeyIdHashAlgorithms();

  /**
   * A string denoting a public key signature system, such as "rsa", "ed25519", and
   * "ecdsa-sha2-nistp256".
   */
  @Gson.Named("keytype")
  String getKeyType();

  /**
   * A dictionary containing the public portion of the key. The contents for TUF sigstore is
   * typically something like: {@code { "public": "04cbc5cab268416....9803" } }
   */
  @Gson.Named("keyval")
  Map<String, String> getKeyVal();

  /**
   * A string denoting a corresponding signature scheme. For example: "rsassa-pss-sha256",
   * "ed25519", and "ecdsa-sha2-nistp256".
   */
  String getScheme();
}
