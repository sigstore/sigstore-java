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
package dev.sigstore.fulcio.client;

import static org.junit.jupiter.api.Named.named;

import com.google.common.io.Resources;
import dev.sigstore.AlgorithmRegistry;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.http.HttpParams;
import dev.sigstore.testing.FakeCTLogServer;
import dev.sigstore.testing.FulcioWrapper;
import dev.sigstore.testing.MockOAuth2ServerExtension;
import dev.sigstore.testing.grpc.GrpcTypes;
import dev.sigstore.trustroot.Service;
import dev.sigstore.tuf.SigstoreTufClient;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class FulcioClientTest {

  static Stream<org.junit.jupiter.api.Named<Function<FulcioWrapper, FulcioClient>>> clients() {
    return Stream.of(
        named(
            "grpc",
            w ->
                FulcioClientGrpc.builder()
                    .setHttpParams(HttpParams.builder().allowInsecureConnections(true).build())
                    .setService(w.getGrpcService())
                    .build()),
        named(
            "http",
            w ->
                FulcioClientHttp.builder()
                    .setHttpParams(HttpParams.builder().allowInsecureConnections(true).build())
                    .setService(w.getHttpService())
                    .build()));
  }

  @ParameterizedTest
  @MethodSource("clients")
  @ExtendWith({FakeCTLogServer.class, MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert(
      Function<FulcioWrapper, FulcioClient> clientFactory,
      MockOAuth2ServerExtension mockOAuthServerExtension,
      FulcioWrapper fulcioWrapper)
      throws Exception {
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);
    var sc = clientFactory.apply(fulcioWrapper).signingCertificate(cReq);

    Assertions.assertTrue(sc.getCertificates().size() > 0);
    Assertions.assertTrue(Certificates.getEmbeddedSCTs(Certificates.getLeaf(sc)).isPresent());
  }

  @ParameterizedTest
  @MethodSource("clients")
  @ExtendWith({MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert_NoSct(
      Function<FulcioWrapper, FulcioClient> clientFactory,
      MockOAuth2ServerExtension mockOAuthServerExtension,
      FulcioWrapper fulcioWrapper)
      throws Exception {
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_2048_SHA256);
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);
    var ex =
        Assertions.assertThrows(
            CertificateException.class,
            () -> clientFactory.apply(fulcioWrapper).signingCertificate(cReq));
    Assertions.assertEquals(ex.getMessage(), "Detached SCTs are not supported");
  }

  @org.junit.jupiter.api.Test
  public void testDecodeCerts() throws Exception {
    var certs =
        GrpcTypes.PemToCertificateChain(
            Resources.toString(
                Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
                StandardCharsets.UTF_8));

    var tufClient = SigstoreTufClient.builder().usePublicGoodInstance().build();
    tufClient.update();
    var signingConfig = tufClient.getSigstoreSigningConfig();
    var fulcioService = Service.select(signingConfig.getCas(), List.of(1)).get();

    var certPath = FulcioClient.decodeCerts(certs);
    Assertions.assertTrue(Certificates.getEmbeddedSCTs(Certificates.getLeaf(certPath)).isPresent());
    Assertions.assertEquals(3, certPath.getCertificates().size());
  }
}
