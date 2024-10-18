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
package dev.sigstore.tuf;

import java.net.URL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class HttpFetcherTest {

  @ParameterizedTest
  @CsvSource({"http://example.com", "http://example.com/"})
  public void newFetcher_urlNoTrailingSlash(String url) throws Exception {
    var fetcher = HttpFetcher.newFetcher(new URL(url));
    Assertions.assertEquals("http://example.com/", fetcher.getSource());
  }
}
