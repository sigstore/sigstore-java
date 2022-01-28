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

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import junit.framework.TestCase;
import org.junit.Assert;

public class GsonSupplierTest extends TestCase {
  private final Gson gson = new GsonSupplier().get();

  public void testWrite() {
    Assert.assertEquals("\"YWJjZA==\"", gson.toJson("abcd".getBytes()));
  }

  public void testRead() {
    Assert.assertArrayEquals("abcd".getBytes(), gson.fromJson("\"YWJjZA==\"", byte[].class));
    Assert.assertArrayEquals(new byte[] {}, gson.fromJson("\"\"", byte[].class));
    Assert.assertArrayEquals(new byte[] {}, gson.fromJson("null", byte[].class));
  }

  public void testReadException() {
    try {
      gson.fromJson("%", byte[].class);
      Assert.fail("Expected JsonParseException but got nothing");
    } catch (JsonParseException e) {
      // pass
    }
  }
}
