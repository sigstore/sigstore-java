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
package dev.sigstore.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class URIFormatTest {

  // Data provider for addTrailingSlash tests
  static Stream<Arguments> addTrailingSlashCases() {
    return Stream.of(
        Arguments.of(
            URI.create("https://example.com/path/"), URI.create("https://example.com/path/")),
        Arguments.of(
            URI.create("https://example.com/path"), URI.create("https://example.com/path/")),
        Arguments.of(URI.create("https://example.com"), URI.create("https://example.com/")),
        Arguments.of(
            URI.create("https://example.com/path?query=1"),
            URI.create("https://example.com/path/?query=1")),
        Arguments.of(
            URI.create("https://example.com/path#fragment"),
            URI.create("https://example.com/path/#fragment")),
        Arguments.of(
            URI.create("https://example.com/path?query=1#fragment"),
            URI.create("https://example.com/path/?query=1#fragment")));
  }

  // Data provider for appendPath tests
  static Stream<Arguments> appendPathCases() {
    return Stream.of(
        Arguments.of(
            URI.create("https://example.com/api/"),
            "users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com/api"),
            "users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com/api/"),
            "/users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com/api"),
            "///users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com/api?key=123"),
            "users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com/api?key=123#section"),
            "users",
            URI.create("https://example.com/api/users")),
        Arguments.of(
            URI.create("https://example.com"),
            "/users/get",
            URI.create("https://example.com/users/get")));
  }

  @ParameterizedTest
  @MethodSource("addTrailingSlashCases")
  void addTrailingSlash(URI input, URI expected) {
    URI result = URIFormat.addTrailingSlash(input);
    assertEquals(expected, result);
  }

  @ParameterizedTest
  @MethodSource("appendPathCases")
  void appendPath(URI base, String path, URI expected) {
    URI result = URIFormat.appendPath(base, path);
    assertEquals(expected, result);
  }
}
