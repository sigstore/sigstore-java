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

import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.Sleeper;
import java.io.IOException;
import java.time.Instant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class UnsuccessfulResponseHandlerTest {
  private static final Instant testNow =
      Instant.ofEpochMilli(1675349494000L); // February 2, 2023 2:51:34 PM GMT
  @Mock private Sleeper sleeper;
  @Mock private ExponentialBackOff exponentialBackOff;
  @InjectMocks private UnsuccessfulResponseHandler testHandler;

  @Mock private HttpResponse httpResponse;
  @Mock private HttpHeaders httpHeaders;

  @Test
  public void testHandleResponse_retryLimit() throws IOException, InterruptedException {
    int count = 0;
    Mockito.when(exponentialBackOff.nextBackOffMillis()).thenReturn(10L);
    Mockito.when(httpResponse.getStatusCode()).thenReturn(500);
    while (testHandler.handleResponse(null, httpResponse, true)) {
      count++;
    }

    Assertions.assertEquals(10, count);
  }

  @ParameterizedTest
  @ValueSource(ints = {500, 509})
  public void testHandleResponse_5xx(int status) throws IOException, InterruptedException {
    Mockito.when(exponentialBackOff.nextBackOffMillis()).thenReturn(10L);
    Mockito.when(httpResponse.getStatusCode()).thenReturn(status);

    var resp = testHandler.handleResponse(null, httpResponse, true);
    Assertions.assertTrue(resp);

    Mockito.verify(exponentialBackOff).nextBackOffMillis();
    Mockito.verify(sleeper).sleep(10L);
    Mockito.verifyNoMoreInteractions(sleeper, exponentialBackOff);
  }

  @ParameterizedTest
  @ValueSource(ints = {500, 509})
  public void testHandleResponse_5xxIgnoreRetryAfter(int status)
      throws IOException, InterruptedException {
    Mockito.when(exponentialBackOff.nextBackOffMillis()).thenReturn(10L);
    Mockito.when(httpResponse.getStatusCode()).thenReturn(status);
    Mockito.when(httpResponse.getHeaders()).thenReturn(httpHeaders);
    Mockito.when(httpHeaders.getRetryAfter()).thenReturn("50");

    var resp = testHandler.handleResponse(null, httpResponse, true);
    Assertions.assertTrue(resp);

    Mockito.verify(exponentialBackOff).nextBackOffMillis();
    Mockito.verify(sleeper).sleep(10L);
    Mockito.verifyNoMoreInteractions(sleeper, exponentialBackOff);
  }

  @ParameterizedTest
  @ValueSource(ints = {429, 503})
  public void testHandleResponse_withRetryAfter(int status)
      throws IOException, InterruptedException {
    Mockito.when(httpResponse.getStatusCode()).thenReturn(status);
    Mockito.when(httpResponse.getHeaders()).thenReturn(httpHeaders);
    Mockito.when(httpHeaders.getRetryAfter()).thenReturn("50");

    var resp = testHandler.handleResponse(null, httpResponse, true);
    Assertions.assertTrue(resp);

    Mockito.verify(sleeper).sleep(50000L);
    Mockito.verifyNoMoreInteractions(sleeper, exponentialBackOff);
  }

  @ParameterizedTest
  @ValueSource(ints = {429, 503})
  public void testHandleResponse_withoutRetryAfter(int status)
      throws IOException, InterruptedException {
    Mockito.when(httpResponse.getStatusCode()).thenReturn(status);
    Mockito.when(httpResponse.getHeaders()).thenReturn(httpHeaders);
    Mockito.when(exponentialBackOff.nextBackOffMillis()).thenReturn(10L);

    var resp = testHandler.handleResponse(null, httpResponse, true);
    Assertions.assertTrue(resp);

    Mockito.verify(exponentialBackOff).nextBackOffMillis();
    Mockito.verify(sleeper).sleep(10L);
    Mockito.verifyNoMoreInteractions(sleeper, exponentialBackOff);
  }

  @Test
  public void testHandleResponse_noRetry() throws IOException {
    var resp = testHandler.handleResponse(null, null, false);
    Assertions.assertFalse(resp);
    Mockito.verifyNoInteractions(sleeper, exponentialBackOff);
  }

  @Test
  public void testHandleResponse_noRetryCode() throws IOException {
    Mockito.when(httpResponse.getStatusCode()).thenReturn(404);

    var resp = testHandler.handleResponse(null, httpResponse, true);
    Assertions.assertFalse(resp);

    Mockito.verify(httpResponse, Mockito.times(1)).getStatusCode();
    Mockito.verifyNoInteractions(sleeper, exponentialBackOff);
  }

  @Test
  public void testCalculateBackoff_httpDate() {
    String httpDate = "Thu, 2 Feb 2023 14:51:54 GMT"; // 20 seconds after "testNow"
    var result = testHandler.calculateBackoff(httpDate, testNow);
    Assertions.assertEquals(20 * 1000, result);
  }

  @Test
  public void testCalculateBackoff_seconds() {
    String seconds = "42";
    var result = testHandler.calculateBackoff(seconds, /* ignored */ testNow);
    Assertions.assertEquals(42 * 1000, result);
  }

  @Test
  public void testCalculateBackoff_badInput() {
    Assertions.assertThrows(
        NumberFormatException.class, () -> testHandler.calculateBackoff("blah", testNow));
  }
}
