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

/**
 * TUF Delegations.
 *
 * @see <a href="https://theupdateframework.github.io/specification/latest/#delegations">TUF
 *     Delegation docs.</a>
 */
@Gson.TypeAdapters
@Value.Immutable
public interface Delegations {

  /**
   * A map of Key IDs to Keys where: <em>KeyID</em> is the identifier of the key signing the ROLE
   * object, which is a hexdigest of the SHA-256 hash of the canonical form of the key. The keyid
   * MUST be unique in the "signatures" array: multiple signatures with th same keyid are not
   * allowed.
   *
   * @return a map if Key IDs to Keys.
   * @see <a href="https://theupdateframework.github.io/specification/latest/#role-keyid">...</a>
   */
  Map<String, Key> getKeys();

  /** A list of delegated roles. */
  List<DelegationRole> getRoles();
}
