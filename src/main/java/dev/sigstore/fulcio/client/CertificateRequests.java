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
package dev.sigstore.fulcio.client;

import dev.sigstore.json.GsonSupplier;
import java.util.HashMap;

public class CertificateRequests {
  public static String toJsonPayload(CertificateRequest cr) {
    HashMap<String, Object> key = new HashMap<>();
    key.put("content", cr.getPublicKey().getEncoded());
    key.put("algorithm", cr.getPublicKey().getAlgorithm());

    HashMap<String, Object> data = new HashMap<>();
    data.put("publicKey", key);
    data.put("signedEmailAddress", cr.getSignedEmailAddress());

    return new GsonSupplier().get().toJson(data);
  }
}
