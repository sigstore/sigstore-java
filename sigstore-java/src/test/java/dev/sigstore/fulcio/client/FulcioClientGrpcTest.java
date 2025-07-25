/*
 * Copyright 2022 The Sigstore Authors.
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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

public class FulcioClientGrpcTest {

  @Test
  @ExtendWith({FakeCTLogServer.class, MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert(
      MockOAuth2ServerExtension mockOAuthServerExtension, FulcioWrapper fulcioWrapper)
      throws Exception {
    // create a "subject" and sign it with the oidc server key (signed JWT)
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    // create a certificate request with our public key and our signed "subject"
    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);

    // ask fulcio for a signing cert
    var client =
        FulcioClientGrpc.builder()
            .setHttpParams(HttpParams.builder().allowInsecureConnections(true).build())
            .setService(fulcioWrapper.getGrpcService())
            .build();

    var sc = client.signingCertificate(cReq);

    // some pretty basic assertions
    Assertions.assertTrue(sc.getCertificates().size() > 0);
    Assertions.assertTrue(Certificates.getEmbeddedSCTs(Certificates.getLeaf(sc)).isPresent());
  }

  @Test
  @ExtendWith({MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert_NoSct(
      MockOAuth2ServerExtension mockOAuthServerExtension, FulcioWrapper fulcioWrapper)
      throws Exception {

    // create a "subject" and sign it with the oidc server key (signed JWT)
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_2048_SHA256);
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    // create a certificate request with our public key and our signed "subject"
    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);

    // ask fulcio for a signing cert
    var client =
        FulcioClientGrpc.builder()
            .setHttpParams(HttpParams.builder().allowInsecureConnections(true).build())
            .setService(fulcioWrapper.getGrpcService())
            .build();
    var ex =
        Assertions.assertThrows(CertificateException.class, () -> client.signingCertificate(cReq));
    Assertions.assertEquals(ex.getMessage(), "Detached SCTs are not supported");
  }

  @Test
  public void testDecode_embeddedGrpc() throws Exception {
    var certs =
        GrpcTypes.PemToCertificateChain(
            Resources.toString(
                Resources.getResource("dev/sigstore/samples/fulcio-response/valid/certWithSct.pem"),
                StandardCharsets.UTF_8));

    var tufClient = SigstoreTufClient.builder().usePublicGoodInstance().build();
    tufClient.update();
    var signingConfig = tufClient.getSigstoreSigningConfig();
    var fulcioService = Service.select(signingConfig.getCas(), List.of(1)).get();

    var signingCert =
        FulcioClientGrpc.builder().setService(fulcioService).build().decodeCerts(certs);
    Assertions.assertTrue(
        Certificates.getEmbeddedSCTs(Certificates.getLeaf(signingCert)).isPresent());
    Assertions.assertEquals(3, signingCert.getCertificates().size());
  }
}
