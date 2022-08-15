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
import org.immutables.gson.Gson;

/**
 * Signed wrapper around {@link TufMeta}.
 *
 * @param <T> the {@code Role} appropriate {@code TufMeta}
 */
public interface SignedTufMeta<T extends TufMeta> {
  /** List of signatures on the Role metadata. */
  List<Signature> getSignatures();

  /** The role metadata that has been signed. */
  @Gson.Named("signed")
  T getSignedMeta();
}
