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

import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;

/** Signed envelope of the Timestamp metadata. */
@Gson.TypeAdapters
@Value.Immutable
public interface Timestamp extends SignedTufMeta<TimestampMeta> {

  @Override
  @Derived
  default TimestampMeta getSignedMeta() {
    return getSignedMeta(TimestampMeta.class);
  }
}
