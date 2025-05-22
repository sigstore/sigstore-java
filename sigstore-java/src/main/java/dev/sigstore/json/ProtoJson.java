/*
 * Copyright 2025 The Sigstore Authors.
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

import com.google.protobuf.util.JsonFormat;
import dev.sigstore.forbidden.SuppressForbidden;

/** Use this instead of JsonFormat to pick up default formatter options for sigstore-java. */
public class ProtoJson {

  /** Default parser to use for sigstore parsing that doesn't fail with unknown fields */
  @SuppressForbidden(reason = "JsonFormat#parser")
  public static JsonFormat.Parser parser() {
    return JsonFormat.parser().ignoringUnknownFields();
  }
}
