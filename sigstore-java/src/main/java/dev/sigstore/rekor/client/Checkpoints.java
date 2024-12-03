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

import com.google.common.base.Splitter;
import dev.sigstore.rekor.client.RekorEntry.Checkpoint;
import dev.sigstore.rekor.client.RekorEntry.CheckpointSignature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Checkpoint helper class to parse from a string in the format described in
 * https://github.com/transparency-dev/formats/blob/12bf59947efb7ae227c12f218b4740fb17a87e50/log/README.md
 */
class Checkpoints {
  private static final Pattern SIGNATURE_BLOCK = Pattern.compile("\\u2014 (\\S+) (\\S+)");

  static Checkpoint from(String encoded) throws RekorParseException {
    var split = Splitter.on("\n\n").splitToList(encoded);
    if (split.size() != 2) {
      throw new RekorParseException(
          "Checkpoint must contain one blank line, delineating the header from the signature block");
    }
    var header = split.get(0);
    var data = split.get(1);

    // note that the string actually contains \n literally, not newlines
    var headers = Splitter.on("\n").splitToList(header);
    if (headers.size() < 3) {
      throw new RekorParseException("Checkpoint header must contain at least 3 lines");
    }

    var origin = headers.get(0);
    long size;
    try {
      size = Long.parseLong(headers.get(1));
    } catch (NumberFormatException nfe) {
      throw new RekorParseException(
          "Checkpoint header attribute size must be a number, but was: " + headers.get(1));
    }
    var base64Hash = headers.get(2);
    // we don't care about any other headers after this

    if (data.length() == 0) {
      throw new RekorParseException("Checkpoint body must contain at least one signature");
    }
    if (!data.endsWith("\n")) {
      throw new RekorParseException("Checkpoint signature section must end with newline");
    }

    List<CheckpointSignature> signatures = new ArrayList<>();
    for (String sig : data.lines().collect(Collectors.toList())) {
      signatures.add(sigFrom(sig));
    }

    return ImmutableCheckpoint.builder()
        .signedData(header + "\n")
        .origin(origin)
        .size(size)
        .base64Hash(base64Hash)
        .addAllSignatures(signatures)
        .build();
  }

  static CheckpointSignature sigFrom(String signatureLine) throws RekorParseException {
    var m = SIGNATURE_BLOCK.matcher(signatureLine);
    if (!m.find()) {
      throw new RekorParseException(
          "Checkpoint signature '"
              + signatureLine
              + "' was not in the format '— <id> <base64 keyhint+signature>'");
    }
    var identity = m.group(1);
    var keySig = Base64.getDecoder().decode(m.group(2));
    if (keySig.length < 5) {
      throw new RekorParseException(
          "Checkpoint signature <keyhint + signature> was "
              + keySig.length
              + " bytes long, but must be at least 5 bytes long");
    }
    var keyHint = Arrays.copyOfRange(keySig, 0, 4);
    var signature = Arrays.copyOfRange(keySig, 4, keySig.length);
    return ImmutableCheckpointSignature.builder()
        .identity(identity)
        .keyHint(keyHint)
        .signature(signature)
        .build();
  }
}
