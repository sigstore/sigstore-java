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
package dev.sigstore.tuf.json;

import static dev.sigstore.tuf.json.TufGsonSupplier.TUF_GSON;

import dev.sigstore.json.GsonChecked;
import dev.sigstore.json.JsonParseException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TufGsonSupplierTest {
  private final GsonChecked gson = TUF_GSON.get();

  @Test
  public void testWrite() {
    Assertions.assertEquals("\"YWJjZA==\"", gson.toJson("abcd".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testRead() throws Exception {
    Assertions.assertArrayEquals(
        "abcd".getBytes(StandardCharsets.UTF_8), gson.fromJson("\"YWJjZA==\"", byte[].class));
    Assertions.assertArrayEquals(new byte[] {}, gson.fromJson("\"\"", byte[].class));
    Assertions.assertArrayEquals(new byte[] {}, gson.fromJson("null", byte[].class));
  }

  @Test
  public void testReadException() {
    try {
      gson.fromJson("%", byte[].class);
      Assertions.fail("Expected JsonParseException but got nothing");
    } catch (JsonParseException e) {
      // pass
    }
  }

  @Test
  public void testLocalDateTime_read() throws Exception {
    var expected = LocalDateTime.of(2023, 1, 12, 18, 22, 2);
    Assertions.assertEquals(
        expected, gson.fromJson("\"2023-01-12T18:22:02Z\"", LocalDateTime.class));
    Assertions.assertEquals(
        expected, gson.fromJson("\"2023-01-12T18:22:02+00:00\"", LocalDateTime.class));
  }

  @Test
  public void testLocalDateTime_readException() {
    Assertions.assertThrows(
        JsonParseException.class, () -> gson.fromJson("\"not-a-date\"", LocalDateTime.class));
  }
}
