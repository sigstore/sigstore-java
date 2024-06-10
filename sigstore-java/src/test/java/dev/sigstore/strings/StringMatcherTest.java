/*
 * Copyright 2024 The Sigstore Authors.
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
package dev.sigstore.strings;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class StringMatcherTest {

  @Test
  public void testString() {
    var testMatcher = StringMatcher.string("testtest");
    Assertions.assertEquals("'String: testtest'", testMatcher.toString());

    Assertions.assertTrue(testMatcher.test("testtest"));
    Assertions.assertFalse(testMatcher.test("testtest1"));
    Assertions.assertFalse(testMatcher.test(""));
    Assertions.assertFalse(testMatcher.test(null));
  }

  @Test
  public void testRegex() throws Exception {
    var testMatcher = StringMatcher.regex("abc...xyz");
    Assertions.assertEquals("'RegEx: abc...xyz'", testMatcher.toString());

    Assertions.assertTrue(testMatcher.test("abc888xyz"));
    Assertions.assertFalse(testMatcher.test("abc888xyzEXTRA"));
    Assertions.assertFalse(testMatcher.test("abcxyz"));
    Assertions.assertFalse(testMatcher.test(""));
    Assertions.assertFalse(testMatcher.test(null));
  }

  @Test
  public void testRegex_initFailure() {
    Assertions.assertThrows(RegexSyntaxException.class, () -> StringMatcher.regex("asdf\\"));
  }
}
