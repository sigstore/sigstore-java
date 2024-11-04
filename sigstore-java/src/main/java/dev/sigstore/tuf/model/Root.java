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

import com.google.common.base.Preconditions;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.immutables.value.Value.Derived;

/** Signed envelope of the Root metadata. */
@Gson.TypeAdapters
@Value.Immutable
public interface Root extends SignedTufMeta<RootMeta> {
  @Override
  @Gson.Ignore
  @Derived
  default RootMeta getSignedMeta() {
    return getSignedMeta(RootMeta.class);
  }

  @Value.Check
  default void checkType() {
    Preconditions.checkState(getSignedMeta().getType().equals("root"));
  }
}
