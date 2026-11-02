/*
 * Copyright 2026 The Sigstore Authors.
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
package dev.sigstore.bundle;

import com.google.common.primitives.Bytes;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DsseEnvelopeTest {

  private static final String IN_TOTO_TYPE = "application/vnd.in-toto+json";

  @Test
  public void getPAE_specExample() {
    // test envelope from https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
    var dsse = envelope("http://example.com/HelloWorld", ascii("hello world"));
    Assertions.assertArrayEquals(
        ascii("DSSEv1 29 http://example.com/HelloWorld 11 hello world"), dsse.getPAE());
  }

  @Test
  public void getPAE_nonAsciiPayload() {
    var payload = "{\"name\":\"café\"}".getBytes(StandardCharsets.UTF_8);
    Assertions.assertArrayEquals(
        Bytes.concat(ascii("DSSEv1 28 application/vnd.in-toto+json 16 "), payload),
        envelope(IN_TOTO_TYPE, payload).getPAE());
  }

  @Test
  public void getPAE_nonAsciiPayloadType() {
    var dsse = envelope("application/vnd.café+json", ascii("{}"));
    Assertions.assertArrayEquals(
        "DSSEv1 26 application/vnd.café+json 2 {}".getBytes(StandardCharsets.UTF_8), dsse.getPAE());
  }

  @Test
  public void getPAE_nonUtf8Payload() {
    // 0xFF never occurs in valid UTF-8
    var payload = new byte[] {'{', (byte) 0xFF, '}'};
    Assertions.assertArrayEquals(
        Bytes.concat(ascii("DSSEv1 28 application/vnd.in-toto+json 3 "), payload),
        envelope(IN_TOTO_TYPE, payload).getPAE());
  }

  private static Bundle.DsseEnvelope envelope(String payloadType, byte[] payload) {
    return ImmutableDsseEnvelope.builder().payloadType(payloadType).payload(payload).build();
  }

  private static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }
}
