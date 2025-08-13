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

import java.net.URI;
import java.net.URISyntaxException;

/**
 * A utility class for formatting URIs, providing predictable path appending.
 *
 * <p>This is preferable to {@link java.net.URI#resolve(String)} for simple path appending, as it
 * avoids {@code resolve()}'s specific handling of base paths without trailing slashes and appended
 * paths with leading slashes.
 */
public final class URIFormat {

  private URIFormat() {}

  /**
   * Ensures the given URI's path has a trailing slash. This method correctly handles URIs with
   * query parameters and fragments.
   *
   * @param input the URI to check.
   * @return a new URI with a trailing slash, or the original URI if it already had one.
   */
  public static URI addTrailingSlash(URI input) {
    String path = input.getPath();
    if (path == null || path.isEmpty()) {
      path = "";
    } else if (path.endsWith("/")) {
      return input;
    }
    try {
      return new URI(
          input.getScheme(),
          input.getAuthority(),
          path + "/",
          input.getQuery(),
          input.getFragment());
    } catch (URISyntaxException e) {
      // This should be unreachable with a valid input URI
      throw new IllegalStateException("Could not append slash to invalid URI: " + input, e);
    }
  }

  /**
   * Appends a path segment to a base URI, ensuring exactly one slash separates them. This method
   * will erase any query parameters or fragments
   *
   * @param base the base URI (e.g., "http://example.com/api?key=1").
   * @param path the path segment to append (e.g., "users" or "/users").
   * @return a new URI with the path appended (e.g., "http://example.com/api/users").
   */
  public static URI appendPath(URI base, String path) {
    String relativePath = path.replaceAll("^/+", "");

    // resolve has some goofy behavior unless we normalize everything before applying
    return addTrailingSlash(base).resolve(relativePath);
  }
}
