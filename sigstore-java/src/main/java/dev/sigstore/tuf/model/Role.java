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

/**
 * TUF uses roles to define the set of actions a party can perform. The concept of roles allows TUF
 * to only trust information provided by the correctly designated party. The root role indicates
 * which roles can sign for which projects.
 *
 * @see <a href="https://theupdateframework.io/metadata/">TUF Role docs</a>
 */
public interface Role {

  enum Name {
    ROOT,
    SNAPSHOT,
    TIMESTAMP,
    TARGETS;

    @Override
    public String toString() {
      return super.toString().toLowerCase();
    }
  }

  /** A list of trusted keys for this role. */
  List<String> getKeyids();

  /** The minimum number of keys required to trust this role's metadata. */
  int getThreshold();
}
