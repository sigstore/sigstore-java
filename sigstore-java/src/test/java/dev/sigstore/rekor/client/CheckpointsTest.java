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
package dev.sigstore.rekor.client;

import com.google.common.io.Resources;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CheckpointsTest {

  public static final String REKOR_PUB_KEYID = "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=";

  public String getResource(String filename) throws IOException {
    return Resources.toString(
        Resources.getResource("dev/sigstore/samples/checkpoints/" + filename),
        StandardCharsets.UTF_8);
  }

  @Test
  public void from_valid() throws Exception {
    var checkpoint = Checkpoints.from(getResource("valid.txt"));
    Assertions.assertEquals("rekor.sigstore.dev - 2605736670972794746", checkpoint.getOrigin());
    Assertions.assertEquals(37795272, checkpoint.getSize());
    Assertions.assertEquals(
        "60ll7idWI1jYRZzxc+jKflYoW+4jWxgZaGR15ASsWt4=", checkpoint.getBase64Hash());

    var keyBytesHintExpected =
        Arrays.copyOfRange(Base64.getDecoder().decode(REKOR_PUB_KEYID), 0, 4);
    var sig = checkpoint.getSignatures().get(0);
    Assertions.assertEquals(1, checkpoint.getSignatures().size());
    Assertions.assertEquals("rekor.sigstore.dev", sig.getIdentity());
    Assertions.assertArrayEquals(keyBytesHintExpected, sig.getKeyHint());
    Assertions.assertEquals(
        "MEYCIQCVZQfYdI9rogwhEGAVwhemHcyP3EzvRZHRVUAO8YiX+gIhAKB+9RSNH9fmN7CWqkBYjw24kiJwqlMbri+jpQzl+lKB",
        Base64.getEncoder().encodeToString(sig.getSignature()));
  }

  @Test
  public void from_validMultiSig() throws Exception {
    var checkpoint = Checkpoints.from(getResource("valid_multi_sig.txt"));
    Assertions.assertEquals("rekor.sigstore.dev - 2605736670972794746", checkpoint.getOrigin());
    Assertions.assertEquals(37795272, checkpoint.getSize());
    Assertions.assertEquals(
        "60ll7idWI1jYRZzxc+jKflYoW+4jWxgZaGR15ASsWt4=", checkpoint.getBase64Hash());

    Assertions.assertEquals(2, checkpoint.getSignatures().size());
    var keyBytesHintExpected =
        Arrays.copyOfRange(Base64.getDecoder().decode(REKOR_PUB_KEYID), 0, 4);

    var sig1 = checkpoint.getSignatures().get(0);
    Assertions.assertEquals("rekor.sigstore.dev", sig1.getIdentity());
    Assertions.assertArrayEquals(keyBytesHintExpected, sig1.getKeyHint());
    Assertions.assertEquals(
        "MEYCIQCVZQfYdI9rogwhEGAVwhemHcyP3EzvRZHRVUAO8YiX+gIhAKB+9RSNH9fmN7CWqkBYjw24kiJwqlMbri+jpQzl+lKB",
        Base64.getEncoder().encodeToString(sig1.getSignature()));

    var sig2 = checkpoint.getSignatures().get(1);
    Assertions.assertEquals("bob.loblaw.dev", sig2.getIdentity());
    Assertions.assertArrayEquals(keyBytesHintExpected, sig2.getKeyHint());
    Assertions.assertEquals(
        "MEYCIQCVZQfYdI9rogwhEGAVwhGmHcyP3EzvRZHRVUAO8YiX+gIhAKB+9RSNH9fmN7CWqkBYjw24kiJwqlMbri+jpQzl+lKB",
        Base64.getEncoder().encodeToString(sig2.getSignature()));
  }

  @Test
  public void from_noSeparator() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_header_body_separator.txt")));
    Assertions.assertEquals(
        "Checkpoint must contain one blank line, delineating the header from the signature block",
        ex.getMessage());
  }

  @Test
  public void from_notEnoughHeaders() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_header_count.txt")));
    Assertions.assertEquals("Checkpoint header must contain at least 3 lines", ex.getMessage());
  }

  @Test
  public void from_notANumber() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_not_a_number.txt")));
    Assertions.assertEquals(
        "Checkpoint header attribute size must be a number, but was: abcdefg", ex.getMessage());
  }

  @Test
  public void from_noSignatures() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_no_signatures.txt")));
    Assertions.assertEquals("Checkpoint body must contain at least one signature", ex.getMessage());
  }

  @Test
  public void from_noNewlineAfterSignatures() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_no_newline_after_signature.txt")));
    Assertions.assertEquals("Checkpoint signature section must end with newline", ex.getMessage());
  }

  @Test
  public void from_signatureFormatInvalid() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_signature_format_invalid.txt")));
    Assertions.assertEquals(
        "Checkpoint signature 'rekor.sigstore.dev wNI9ajBGAiEAlWUH2HSPa6IMIRBgFcIXph3Mj9xM70WR0VVADvGIl/oCIQCgfvUUjR/X5jewlqpAWI8NuJIicKpTG64vo6UM5fpSgQ==' was not in the format '— <id> <base64 keyhint+signature>'",
        ex.getMessage());
  }

  @Test
  public void from_signatureLengthInsufficient() throws Exception {
    var ex =
        Assertions.assertThrows(
            RekorParseException.class,
            () -> Checkpoints.from(getResource("error_signature_length_insufficient.txt")));
    Assertions.assertEquals(
        "Checkpoint signature <keyhint + signature> was 4 bytes long, but must be at least 5 bytes long",
        ex.getMessage());
  }
}
