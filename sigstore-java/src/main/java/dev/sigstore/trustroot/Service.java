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

import dev.sigstore.proto.trustroot.v1.ServiceConfiguration;
import java.net.URI;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import org.immutables.value.Value.Immutable;

@Immutable
public interface Service {

  /** The URL of the remote service infrastructure piece. */
  URI getUrl();

  /** The API version of the service. */
  int getApiVersion();

  /** The validity window in which this service may be used for signing. */
  ValidFor getValidFor();

  static Service from(dev.sigstore.proto.trustroot.v1.Service service) {
    return ImmutableService.builder()
        .apiVersion(service.getMajorApiVersion())
        .validFor(ValidFor.from(service.getValidFor()))
        .url(URI.create(service.getUrl()))
        .build();
  }

  /**
   * INTERNAL ONLY: Returns a default Service object for a url that is valid forever. Only used
   * transitionally as we adopt SigningConfig throughout the ecosystem.
   */
  static Service of(URI url, int apiVersion) {
    return ImmutableService.builder()
        .apiVersion(apiVersion)
        .validFor(ImmutableValidFor.builder().start(Instant.now()).build())
        .url(url)
        .build();
  }

  /**
   * Return a single service that is currently valid, that also exposes an api version supported by
   * this client. If multiple services match that criteria, filter by those services with the
   * highest apiVersion and further sort by services that were started most recently.
   *
   * @param services the service list
   * @param apiVersions an list of api version this clients supports
   * @return A service if found
   */
  static Optional<Service> select(List<Service> services, List<Integer> apiVersions) {
    OptionalInt maxApiVersionMaybe =
        services.stream().mapToInt(Service::getApiVersion).filter(apiVersions::contains).max();

    if (maxApiVersionMaybe.isEmpty()) {
      return Optional.empty();
    }

    int maxApiVersion = maxApiVersionMaybe.getAsInt();

    return services.stream()
        .filter(s -> s.getValidFor().contains(Instant.now()))
        .filter(s -> s.getApiVersion() == maxApiVersion)
        .max(Comparator.comparingLong(s -> s.getValidFor().getStart().toEpochMilli()));
  }

  @Immutable
  interface Config {
    enum Selector {
      ANY,
      EXACT,
      ALL
    }

    // the number to select when selector is EXACT
    OptionalInt getCount();

    // the selector type
    Selector getSelector();

    static Config from(ServiceConfiguration config) throws SigstoreConfigurationException {
      switch (config.getSelector()) {
        case ANY:
          return ImmutableConfig.builder().selector(Selector.ANY).build();
        case EXACT:
          return ImmutableConfig.builder()
              .selector(Selector.EXACT)
              .count(config.getCount())
              .build();
        case ALL:
          return ImmutableConfig.builder().selector(Selector.ALL).build();
        default:
          throw new SigstoreConfigurationException(
              "Cannot parse signing configuration selector: " + config.getSelector());
      }
    }

    /**
     * INTERNAL ONLY: Returns the default config of ANY, only used transitionally as we adopt
     * SigningConfig throughout the ecosystem.
     */
    static Config ofAny() {
      return ImmutableConfig.builder().selector(Selector.ANY).build();
    }
  }
}
