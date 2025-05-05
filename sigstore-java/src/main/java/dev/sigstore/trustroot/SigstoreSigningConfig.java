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

import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.trustroot.v1.SigningConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import org.immutables.value.Value.Immutable;

/**
 * Sigstore configuration to identify signing infrastructure pieces and the policy for using them
 * during a singing event.
 */
@Immutable
public interface SigstoreSigningConfig {

  List<Service> getCas();

  List<Service> getTsas();

  List<Service> getTLogs();

  // The default sigstore provided oidc providers
  List<Service> getOidcProviders();

  Service.Config getTsaConfig();

  Service.Config getTLogConfig();

  static SigstoreSigningConfig from(SigningConfig proto) throws SigstoreConfigurationException {
    if (!proto.getMediaType().equals("application/vnd.dev.sigstore.signingconfig.v0.2+json")) {
      throw new SigstoreConfigurationException(
          "Unsupported signing config mediaType: " + proto.getMediaType());
    }

    return ImmutableSigstoreSigningConfig.builder()
        .addAllCas(protoToServiceList(proto.getCaUrlsList()))
        .addAllTLogs(protoToServiceList(proto.getRekorTlogUrlsList()))
        .addAllOidcProviders(protoToServiceList(proto.getOidcUrlsList()))
        .addAllTsas(protoToServiceList(proto.getTsaUrlsList()))
        .tsaConfig(Service.Config.from(proto.getTsaConfig()))
        .tLogConfig(Service.Config.from(proto.getRekorTlogConfig()))
        .build();
  }

  static SigstoreSigningConfig from(InputStream json) throws SigstoreConfigurationException {
    var signingConfigBuilder = SigningConfig.newBuilder();
    try (var reader = new InputStreamReader(json, StandardCharsets.UTF_8)) {
      JsonFormat.parser().merge(reader, signingConfigBuilder);
    } catch (IOException ex) {
      throw new SigstoreConfigurationException("Could not parse signing configuration", ex);
    }
    return from(signingConfigBuilder.build());
  }

  private static List<Service> protoToServiceList(
      List<dev.sigstore.proto.trustroot.v1.Service> serviceList) {
    return serviceList.stream().map(Service::from).collect(Collectors.toList());
  }
}
