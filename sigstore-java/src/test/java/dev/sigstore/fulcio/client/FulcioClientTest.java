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

import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.http.ImmutableHttpParams;
import dev.sigstore.testing.FakeCTLogServer;
import dev.sigstore.testing.FulcioWrapper;
import dev.sigstore.testing.MockOAuth2ServerExtension;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

public class FulcioClientTest {

  @Test
  @ExtendWith({FakeCTLogServer.class, MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert(
      MockOAuth2ServerExtension mockOAuthServerExtension, FulcioWrapper fulcioWrapper)
      throws Exception {
    var c =
        FulcioClient.builder()
            .setHttpParams(ImmutableHttpParams.builder().allowInsecureConnections(true).build())
            .setServerUrl(fulcioWrapper.getGrpcURI())
            .build();

    // create a "subject" and sign it with the oidc server key (signed JWT)
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.newEcdsaSigner();
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    // create a certificate request with our public key and our signed "subject"
    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);

    // ask fulcio for a signing cert
    var sc = c.signingCertificate(cReq);

    // some pretty basic assertions
    Assertions.assertTrue(sc.getCertPath().getCertificates().size() > 0);
    Assertions.assertTrue(sc.getDetachedSct().isEmpty());
    Assertions.assertTrue(sc.hasEmbeddedSct());
  }

  @Test
  @ExtendWith({MockOAuth2ServerExtension.class, FulcioWrapper.class})
  public void testSigningCert_NoSct(
      MockOAuth2ServerExtension mockOAuthServerExtension, FulcioWrapper fulcioWrapper)
      throws Exception {
    var c =
        FulcioClient.builder()
            .setHttpParams(ImmutableHttpParams.builder().allowInsecureConnections(true).build())
            .setServerUrl(fulcioWrapper.getGrpcURI())
            .requireSct(false)
            .build();

    // create a "subject" and sign it with the oidc server key (signed JWT)
    var token = mockOAuthServerExtension.getOidcToken().getIdToken();
    var subject = mockOAuthServerExtension.getOidcToken().getSubjectAlternativeName();

    var signer = Signers.newRsaSigner();
    var signed = signer.sign(subject.getBytes(StandardCharsets.UTF_8));

    // create a certificate request with our public key and our signed "subject"
    var cReq = CertificateRequest.newCertificateRequest(signer.getPublicKey(), token, signed);

    // ask fulcio for a signing cert
    var sc = c.signingCertificate(cReq);

    // some pretty basic assertions
    Assertions.assertTrue(sc.getCertPath().getCertificates().size() > 0);
    Assertions.assertFalse(sc.getDetachedSct().isPresent());
    Assertions.assertFalse(sc.hasEmbeddedSct());
  }

  @Test
  @Disabled("TODO: until we can hit a fulcio instance that generates detached SCTs")
  public void testSigningCert_detachedSCT() {}
}
