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
package dev.sigstore.tuf;

import dev.sigstore.tuf.model.Signature;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Thrown when the metadata has signatures from the same key even if the threshold is met. <a
 * href="https://theupdateframework.github.io/specification/latest/#file-formats-object-format">4.2.1</a>
 */
public class DuplicateKeyIdsException extends TufException {

  private final List<Signature> signatures;
  private final String keyId;

  public DuplicateKeyIdsException(List<Signature> signatures, String keyId) {
    super(
        String.format(
            Locale.ROOT,
            "The role has multiple signatures with the same key_id. [Signatures: %s, KeyId: %s]",
            signatures.stream()
                .map(Signature::getSignature)
                .collect(Collectors.joining(",", "(", ")")),
            keyId));
    this.signatures = signatures;
    this.keyId = keyId;
  }

  public List<Signature> getSignatures() {
    return signatures;
  }

  public String getKeyId() {
    return keyId;
  }
}
