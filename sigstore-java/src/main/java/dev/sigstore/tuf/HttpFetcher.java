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
package dev.sigstore.tuf;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.json.gson.GsonFactory;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

public class HttpFetcher implements Fetcher {

  private final URL mirror;

  private HttpFetcher(URL mirror) {
    this.mirror = mirror;
  }

  public static HttpFetcher newFetcher(URL mirror) throws MalformedURLException {
    if (mirror.toString().endsWith("/")) {
      return new HttpFetcher(mirror);
    }
    return new HttpFetcher(new URL(mirror.toExternalForm() + "/"));
  }

  @Override
  public String getSource() {
    return mirror.toString();
  }

  @Override
  public byte[] fetchResource(String filename, int maxLength)
      throws IOException, FileExceedsMaxLengthException {
    GenericUrl fileUrl = new GenericUrl(mirror + filename);
    var req =
        HttpClients.newHttpTransport(HttpParams.builder().build())
            .createRequestFactory(
                request ->
                    request.setParser(GsonFactory.getDefaultInstance().createJsonObjectParser()))
            .buildGetRequest(fileUrl);
    req.getHeaders().setAccept("application/json; api-version=2.0");
    req.getHeaders().setContentType("application/json");
    req.setThrowExceptionOnExecuteError(false);
    var resp = req.execute();
    if (resp.getStatusCode() == 404) {
      return null;
    }
    if (resp.getStatusCode() != 200) {
      throw new TufException(
          String.format(
              Locale.ROOT,
              "Unexpected return from mirror(%s). Status code: %s, status message: %s",
              mirror,
              resp.getStatusCode(),
              resp.getStatusMessage()));
    }
    byte[] roleBytes = resp.getContent().readNBytes(maxLength);
    if (roleBytes.length == maxLength && resp.getContent().read() != -1) {
      throw new FileExceedsMaxLengthException(fileUrl.toString(), maxLength);
    }
    return roleBytes;
  }
}
