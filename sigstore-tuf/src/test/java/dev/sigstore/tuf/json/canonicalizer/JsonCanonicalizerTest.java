/*
 * Copyright 2026 The Sigstore Authors.
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
package dev.sigstore.tuf.json.canonicalizer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JsonCanonicalizerTest {

  @Test
  void canonicalize_sortsKeysAndPreservesLiteralNewlines() throws IOException {
    var canonicalizer = new JsonCanonicalizer("{ \"b\": 1.0, \"a\": \"line1\\nline2\" }");
    assertThat(canonicalizer.getEncodedString()).isEqualTo("{\"a\":\"line1\nline2\",\"b\":1}");
  }

  @Test
  void nestedObjects_atMaxDepth_succeeds() throws IOException {
    String json = nestedObjects(JsonDecoder.MAX_NESTING_DEPTH);
    var canonicalizer = new JsonCanonicalizer(json);
    assertThat(canonicalizer.getEncodedString()).isEqualTo(json);
  }

  @Test
  void nestedObjects_exceedingMaxDepth_throwsIOException() {
    String overByOne = nestedObjects(JsonDecoder.MAX_NESTING_DEPTH + 1);
    assertThatThrownBy(() -> new JsonCanonicalizer(overByOne))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maximum nesting depth exceeded");

    // Regression test for OSS-Fuzz issue 587351905 (deeply nested unclosed objects)
    byte[] deeplyNested = "{\"\":".repeat(6000).getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> new JsonCanonicalizer(deeplyNested))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maximum nesting depth exceeded");
  }

  @Test
  void nestedArrays_atMaxDepth_succeeds() throws IOException {
    String json = nestedArrays(JsonDecoder.MAX_NESTING_DEPTH);
    var canonicalizer = new JsonCanonicalizer(json);
    assertThat(canonicalizer.getEncodedString()).isEqualTo(json);
  }

  @Test
  void nestedArrays_exceedingMaxDepth_throwsIOException() {
    String overByOne = nestedArrays(JsonDecoder.MAX_NESTING_DEPTH + 1);
    assertThatThrownBy(() -> new JsonCanonicalizer(overByOne))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maximum nesting depth exceeded");

    String deeplyNested = "[".repeat(6000);
    assertThatThrownBy(() -> new JsonCanonicalizer(deeplyNested))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maximum nesting depth exceeded");
  }

  @Test
  void mixedNestedObjectsAndArrays_atMaxDepth_succeeds() throws IOException {
    // 127 * 2 + 1 ("{}") = 255 == MAX_NESTING_DEPTH
    String mixed = "{\"a\":[".repeat(127) + "{}" + "]}".repeat(127);
    var canonicalizer = new JsonCanonicalizer(mixed);
    assertThat(canonicalizer.getEncodedString()).isEqualTo(mixed);
  }

  @Test
  void mixedNestedObjectsAndArrays_exceedingMaxDepth_throwsIOException() {
    // Each "{\"a\":[" adds 2 levels of nesting; 128 * 2 = 256 > 255
    String mixed = "{\"a\":[".repeat(128) + "1" + "]}".repeat(128);
    assertThatThrownBy(() -> new JsonCanonicalizer(mixed))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maximum nesting depth exceeded");
  }

  @Test
  void manySiblingObjectsAndArrays_succeeds() throws IOException {
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < 500; i++) {
      if (i > 0) {
        sb.append(',');
      }
      sb.append("{\"arr\":[1,2],\"i\":").append(i).append('}');
    }
    sb.append(']');

    var canonicalizer = new JsonCanonicalizer(sb.toString());
    assertThat(canonicalizer.getEncodedString()).isEqualTo(sb.toString());
  }

  private static String nestedObjects(int depth) {
    return "{\"a\":".repeat(depth - 1) + "{}" + "}".repeat(depth - 1);
  }

  private static String nestedArrays(int depth) {
    return "[".repeat(depth) + "]".repeat(depth);
  }
}
