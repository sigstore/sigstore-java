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
package dev.sigstore.json;

import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Base64;

/** Converts byte arrays to base64, not url safe */
class GsonByteArrayAdapter extends TypeAdapter<byte[]> {
  @Override
  public void write(JsonWriter out, byte[] value) throws IOException {
    out.value(Base64.getEncoder().encodeToString(value));
  }

  @Override
  public byte[] read(JsonReader in) {
    try {
      if (in.peek() == JsonToken.NULL) {
        in.nextNull();
        return new byte[] {};
      }
      String byteValue = in.nextString();
      if (byteValue != null) {
        return Base64.getDecoder().decode(byteValue);
      }
      return new byte[] {};
    } catch (Exception e) {
      throw new JsonParseException(e);
    }
  }
}
