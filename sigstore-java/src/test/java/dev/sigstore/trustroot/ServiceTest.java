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
package dev.sigstore.trustroot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.Timestamp;
import dev.sigstore.proto.common.v1.TimeRange;
import dev.sigstore.proto.trustroot.v1.ServiceConfiguration;
import dev.sigstore.proto.trustroot.v1.ServiceSelector;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ServiceTest {

  private static URI testUri;

  private static Service serviceV1Valid;
  private static Service serviceV1Expired;
  private static Service serviceV1Future;
  private static Service serviceV2Valid;
  private static Service serviceV2ValidNewer;

  @BeforeAll
  static void setUp() throws Exception {
    testUri = new URI("https://service.example.com");
    var now = Instant.now();
    var oneday = Duration.ofDays(1);
    var twodays = Duration.ofDays(2);

    // Current valid (starting yesterday)
    var validNow = ImmutableValidFor.builder().start(now.minus(oneday)).build();
    // Currently valid (starting now)
    var validNowStartingNow = ImmutableValidFor.builder().start(now).build();
    // Expired yesterday
    var validPast =
        ImmutableValidFor.builder().start(now.minus(twodays)).end(now.minus(oneday)).build();
    // Only starts tomorrow
    var validFuture =
        ImmutableValidFor.builder().start(now.plus(oneday)).end(now.plus(twodays)).build();

    serviceV1Valid =
        ImmutableService.builder()
            .url(new URI("https://v1.example.com"))
            .apiVersion(1)
            .validFor(validNow)
            .build();
    serviceV1Expired =
        ImmutableService.builder()
            .url(new URI("https://v1expired.example.com"))
            .apiVersion(1)
            .validFor(validPast)
            .build();
    serviceV1Future =
        ImmutableService.builder()
            .url(new URI("https://v1future.example.com"))
            .apiVersion(1)
            .validFor(validFuture)
            .build();
    serviceV2Valid =
        ImmutableService.builder()
            .url(new URI("https://v2.example.com"))
            .apiVersion(2)
            .validFor(validNow)
            .build();
    serviceV2ValidNewer =
        ImmutableService.builder()
            .url(new URI("https://v2newer.example.com"))
            .apiVersion(2)
            .validFor(validNowStartingNow)
            .build();
  }

  @Test
  void testFrom_ProtoService() {
    Timestamp startTimestamp =
        Timestamp.newBuilder().setSeconds(Instant.now().getEpochSecond()).build();

    TimeRange protoTimeRange = TimeRange.newBuilder().setStart(startTimestamp).build();

    var protoService =
        dev.sigstore.proto.trustroot.v1.Service.newBuilder()
            .setUrl(testUri.toString())
            .setMajorApiVersion(1)
            .setValidFor(protoTimeRange)
            .build();

    Service service = Service.from(protoService);
    ValidFor validFor = ValidFor.from(protoService.getValidFor());

    assertEquals(testUri, service.getUrl());
    assertEquals(1, service.getApiVersion());
    assertEquals(validFor, service.getValidFor());
    assertFalse(service.getValidFor().getEnd().isPresent());
  }

  static Stream<Arguments> selectTestInputs() {
    return Stream.of(
        Arguments.of("Empty returns empty", List.of(), List.of(1), Optional.<Service>empty()),
        Arguments.of(
            "No matching api version",
            List.of(serviceV1Valid),
            List.of(2, 3),
            Optional.<Service>empty()),
        Arguments.of(
            "No matching validity period",
            List.of(serviceV1Expired, serviceV1Future),
            List.of(1),
            Optional.<Service>empty()),
        Arguments.of(
            "Simple match", List.of(serviceV1Valid), List.of(1), Optional.of(serviceV1Valid)),
        Arguments.of(
            "Match on api and validity",
            List.of(serviceV1Expired, serviceV1Valid, serviceV1Future),
            List.of(1),
            Optional.of(serviceV1Valid)),
        Arguments.of(
            "Match newest start time",
            List.of(serviceV2Valid, serviceV2ValidNewer),
            List.of(2),
            Optional.of(serviceV2ValidNewer)),
        Arguments.of(
            "Matches largest api version and newest start time",
            List.of(serviceV1Valid, serviceV2Valid, serviceV2ValidNewer),
            List.of(1, 2),
            Optional.of(serviceV2ValidNewer)));
  }

  @ParameterizedTest
  @MethodSource("selectTestInputs")
  void testSelect(
      String name, List<Service> services, List<Integer> apiVersions, Optional<Service> expected) {
    Optional<Service> result = Service.select(services, apiVersions);
    assertEquals(expected, result, name + " failed");
  }

  static Stream<Arguments> configFromTestInputs() {
    return Stream.of(
        Arguments.of(ServiceSelector.ANY, 0, Service.Config.Selector.ANY, OptionalInt.empty()),
        Arguments.of(ServiceSelector.ALL, 5, Service.Config.Selector.ALL, OptionalInt.empty()),
        Arguments.of(ServiceSelector.EXACT, 3, Service.Config.Selector.EXACT, OptionalInt.of(3)));
  }

  @ParameterizedTest
  @MethodSource("configFromTestInputs")
  void testConfigFrom(
      ServiceSelector protoSelector,
      int protoCountValue,
      Service.Config.Selector expectedSelector,
      OptionalInt expectedCount)
      throws SigstoreConfigurationException {
    // Build proto config using builder
    ServiceConfiguration protoConfig =
        ServiceConfiguration.newBuilder()
            .setSelector(protoSelector)
            .setCount(protoCountValue)
            .build();

    Service.Config config = Service.Config.from(protoConfig);

    assertEquals(expectedSelector, config.getSelector());
    assertEquals(expectedCount, config.getCount());
  }

  @Test
  void testConfigFrom_UnrecognizedThrowsException() {
    ServiceConfiguration protoConfig =
        ServiceConfiguration.newBuilder()
            .setSelector(
                ServiceSelector
                    .SERVICE_SELECTOR_UNDEFINED) // Or potentially .setSelectorValue(-1) if allowed
            .build();

    SigstoreConfigurationException exception =
        assertThrows(SigstoreConfigurationException.class, () -> Service.Config.from(protoConfig));
    assertEquals(
        "Cannot parse signing configuration selector: SERVICE_SELECTOR_UNDEFINED",
        exception.getMessage());
  }
}
