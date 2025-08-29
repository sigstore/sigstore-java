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
package dev.sigstore.tuf.cli;

import java.time.Clock;

public class TestClock {
  private static Clock clock = null;

  public static void set(Clock clock) {
    TestClock.clock = clock;
  }

  public static Clock get() {
    return clock == null ? Clock.systemUTC() : clock;
  }

  public static void reset() {
    TestClock.clock = null;
  }
}
