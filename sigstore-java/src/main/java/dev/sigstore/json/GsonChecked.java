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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import java.io.Reader;
import java.lang.reflect.Type;

/** A Gson wrapper that catches all runtime exceptions. */
public final class GsonChecked {

  Gson gson;

  GsonChecked(Gson gson) {
    this.gson = gson;
  }

  public <T> T fromJson(JsonElement element, Class<T> classOfT) throws JsonParseException {
    try {
      return gson.fromJson(element, classOfT);
    } catch (RuntimeException e) {
      throw new JsonParseException(e);
    }
  }

  public <T> T fromJson(String json, Class<T> classOfT) throws JsonParseException {
    try {
      return gson.fromJson(json, classOfT);
    } catch (RuntimeException e) {
      throw new JsonParseException(e);
    }
  }

  public <T> T fromJson(String json, Type typeOfT) throws JsonParseException {
    try {
      return gson.fromJson(json, typeOfT);
    } catch (RuntimeException e) {
      throw new JsonParseException(e);
    }
  }

  public <T> T fromJson(Reader reader, Class<T> classOfT) throws JsonParseException {
    try {
      return gson.fromJson(reader, classOfT);
    } catch (RuntimeException e) {
      throw new JsonParseException(e);
    }
  }

  public <T> String toJson(T src) {
    return gson.toJson(src);
  }

  public <T> void toJson(T src, Appendable writer) {
    gson.toJson(src, writer);
  }
}
