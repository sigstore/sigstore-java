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
package dev.sigstore.testing.matchers;

import com.google.common.collect.ImmutableList;
import java.util.Arrays;
import java.util.List;
import org.mockito.ArgumentMatcher;

/**
 * Custom matcher for objects of type List<byte[]> since equality on arrays nested in lists gets a
 * bit wonky.
 */
public class ByteArrayListMatcher implements ArgumentMatcher<List<byte[]>> {
  private final List<byte[]> expected;

  public ByteArrayListMatcher(List<byte[]> expected) {
    this.expected = ImmutableList.copyOf(expected);
  }

  @Override
  public boolean matches(List<byte[]> actual) {
    if (expected.size() != actual.size()) {
      return false;
    }
    for (int i = 0; i < expected.size(); i++) {
      if (!Arrays.equals(expected.get(i), actual.get(i))) {
        return false;
      }
    }
    return true;
  }
}
