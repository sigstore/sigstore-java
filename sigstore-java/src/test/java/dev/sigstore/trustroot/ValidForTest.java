/*
 * Copyright 2023 The Sigstore Authors.
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
package dev.sigstore.trustroot;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ValidForTest {

  @Test
  public void contains_withStartAndEnd() {
    var start = Instant.now().minus(10, ChronoUnit.MINUTES);
    var end = Instant.now().plus(10, ChronoUnit.MINUTES);
    var range = ImmutableValidFor.builder().start(start).end(end).build();

    Assertions.assertTrue(range.contains(Instant.now()));

    Assertions.assertTrue(range.contains(start.plus(10, ChronoUnit.SECONDS)));
    Assertions.assertTrue(range.contains(start));
    Assertions.assertFalse(range.contains(start.minus(10, ChronoUnit.SECONDS)));

    Assertions.assertTrue(range.contains(end.minus(10, ChronoUnit.SECONDS)));
    Assertions.assertTrue(range.contains(end));
    Assertions.assertFalse(range.contains(end.plus(10, ChronoUnit.SECONDS)));
  }

  public void contains_withNoEnd() {
    var start = Instant.now().minus(10, ChronoUnit.MINUTES);
    var range = ImmutableValidFor.builder().start(start).build();

    Assertions.assertTrue(range.contains(Instant.now()));
    Assertions.assertTrue(range.contains(Instant.now().plus(10, ChronoUnit.SECONDS)));

    Assertions.assertTrue(range.contains(start.plus(10, ChronoUnit.SECONDS)));
    Assertions.assertTrue(range.contains(start));
    Assertions.assertFalse(range.contains(start.minus(10, ChronoUnit.SECONDS)));
  }
}
