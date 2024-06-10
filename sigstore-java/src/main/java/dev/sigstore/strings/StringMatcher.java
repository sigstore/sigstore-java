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

import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * An interface for allowing direct string matching or regular expressions. Use the static factory
 * {@link #string(String)} or {@link #regex(String)} to instantiate the appropriate matcher. Custom
 * implementations should override {@link Object#toString} for better error reporting.
 */
public interface StringMatcher extends Predicate<String> {

  /** Create a matcher for string equality. */
  static StringMatcher string(String string) {
    Objects.requireNonNull(string, "string matcher cannot be initialized with null string");
    return new StringMatcher() {
      @Override
      public boolean test(String target) {
        return string.equals(target);
      }

      @Override
      public String toString() {
        return "'String: " + string + "'";
      }
    };
  }

  /**
   * Create a matcher using regular expressions. Regex matching ignores null values and returns
   * false instead of erroring.
   *
   * @param string the input pattern
   * @return a regex based instance
   * @throws RegexSyntaxException if the input pattern is not valid regex. This is a runtime
   *     exception and probably should be handled
   */
  static StringMatcher regex(String string) throws RegexSyntaxException {
    Objects.requireNonNull(string, "string matcher cannot be initialized with null regex");
    Pattern pattern;
    try {
      pattern = Pattern.compile(string);
    } catch (PatternSyntaxException ex) {
      throw new RegexSyntaxException("Could not parse regex: '" + string + "'", ex);
    }
    return new StringMatcher() {
      @Override
      public boolean test(String target) {
        if (target == null) {
          return false;
        }
        return pattern.matcher(target).matches();
      }

      @Override
      public String toString() {
        return "'RegEx: " + pattern + "'";
      }
    };
  }
}
