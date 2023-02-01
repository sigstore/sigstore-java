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
package dev.sigstore.http;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpUnsuccessfulResponseHandler;
import com.google.api.client.util.BackOff;
import com.google.api.client.util.BackOffUtils;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.Sleeper;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.time.Instant;
import java.util.logging.Logger;
import org.apache.http.client.utils.DateUtils;

/**
 * Handler for 429 and standard server errors 5XX. Objects of this class are single use. A new
 * instance should be created for each request (but this is handled in {@link
 * HttpClients#newRequestFactory(HttpParams)}).
 *
 * <p>This implementation is a bit weird, but hopefully we can just move to grpc for rekor when
 * ready.
 */
public class UnsuccessfulResponseHandler implements HttpUnsuccessfulResponseHandler {
  // handler may return before 10 retries if exponentialBackoff hits its limit first
  private static final int MAX_RETRIES = 10;
  private static final Logger log = Logger.getLogger(UnsuccessfulResponseHandler.class.getName());

  private final Sleeper sleeper;
  private final BackOff exponentialBackOff;

  private int currentRetries = 0;

  public static UnsuccessfulResponseHandler newUnsuccessfulResponseHandler() {
    return new UnsuccessfulResponseHandler(Sleeper.DEFAULT, new ExponentialBackOff());
  }

  @VisibleForTesting
  UnsuccessfulResponseHandler(Sleeper sleeper, ExponentialBackOff exponentialBackOff) {
    this.sleeper = sleeper;
    this.exponentialBackOff = exponentialBackOff;
  }

  @Override
  public boolean handleResponse(HttpRequest request, HttpResponse response, boolean supportsRetry)
      throws IOException {
    if (!supportsRetry) {
      return false;
    }
    if (currentRetries >= MAX_RETRIES) {
      return false;
    }
    currentRetries++;

    var statusCode = response.getStatusCode();
    // we only retry 5XX and 429
    if (!(statusCode / 100 == 5 || statusCode == 429)) {
      return false;
    }
    try {
      var headers = response.getHeaders();
      if (headers != null) {
        var retryAfter = headers.getRetryAfter();
        // we only use Retry-After on 503 and 429
        if (retryAfter != null && (statusCode == 429 || statusCode == 503)) {
          try {
            return handleRetryAfter(retryAfter);
          } catch (NumberFormatException ignored) {
            // ignored this is a parse error from Retry-After, just go to exponential backoff
            // but maybe pop off a warning so we can inform the infrastructure owners
            log.warning(
                "Retry-After header in request to "
                    + request.getUrl()
                    + " was invalid ("
                    + retryAfter
                    + ")");
          }
        }
      }
      return BackOffUtils.next(sleeper, exponentialBackOff);
    } catch (InterruptedException exception) {
      // Mark thread as interrupted since we cannot throw InterruptedException here.
      Thread.currentThread().interrupt();
    }
    return false;
  }

  // Retry-After: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
  private boolean handleRetryAfter(String retryAfter) throws InterruptedException, IOException {
    var delay = calculateBackoff(retryAfter, Instant.now());
    if (delay > 0) {
      sleeper.sleep(delay);
    }
    return true;
  }

  // backoff in milliseconds
  @VisibleForTesting
  long calculateBackoff(String retryAfter, Instant now) throws NumberFormatException {
    // parse as httpdate
    var date = DateUtils.parseDate(retryAfter);
    if (date != null) {
      return date.toInstant().toEpochMilli() - now.toEpochMilli();
    }

    // parse as seconds (or throw NumberFormatException)
    return Long.parseLong(retryAfter) * 1000;
  }
}
