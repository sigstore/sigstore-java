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
package dev.sigstore.bundle;

import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.google.protobuf.ByteString;
import com.google.protobuf.MessageOrBuilder;
import dev.sigstore.proto.bundle.v1.Bundle;
import dev.sigstore.proto.common.v1.LogId;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class BundleVerifierTest {
  static Iterable<Arguments> findMissingFields_data() {
    return List.of(
        arguments("LogId.newBuilder()", LogId.newBuilder(), List.of("key_id")),
        arguments(
            "LogId.newBuilder().setKeyId(empty)",
            LogId.newBuilder().setKeyId(ByteString.EMPTY),
            List.of("key_id")),
        arguments(
            "LogId.newBuilder().setKeyId(\"cafe\")",
            LogId.newBuilder().setKeyId(ByteString.fromHex("cafe")),
            List.of()),
        arguments(
            "Sigstore Bundle", Bundle.newBuilder(), List.of("verification_material", "content")));
  }

  @ParameterizedTest
  @MethodSource("findMissingFields_data")
  void findMissingFields(String name, MessageOrBuilder message, List<String> missingFields) {
    Assertions.assertThat(BundleVerifier.findMissingFields(message))
        .describedAs(name)
        .isEqualTo(missingFields);
  }
}
