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

import static com.google.common.io.Files.write;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ClientTest {
  @Rule public TemporaryFolder testRoot = new TemporaryFolder();

  @Test
  public void testSigningCert() throws Exception {
    // TODO: convert all these fixtures into junit rules/extensions
    // start oidc server
    try (FakeOIDCServer oidcServer = FakeOIDCServer.startNewServer()) {
      File fulcioConfig = testRoot.newFile("fulcio-config.json");
      write(oidcServer.getFulcioConfig().getBytes(StandardCharsets.UTF_8), fulcioConfig);
      try (FakeCTLogServer ctLogServer = FakeCTLogServer.startNewServer()) {

        // start fulcio client with config from oidc server
        try (FulcioWrapper fulcioServer =
            FulcioWrapper.startNewServer(fulcioConfig, ctLogServer.getURI().toString())) {
          Client c = Client.Builder().setServerUrl(fulcioServer.getURI()).build();

          // create a "subject" and sign it with the oidc server key (signed JWT)
          String subject = oidcServer.USER;
          String token = oidcServer.sign(subject);

          // create an ECDSA p-256 keypair, this is our key that we want to generate certs for
          KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
          keyGen.initialize(256);
          KeyPair keys = keyGen.generateKeyPair();

          // sign the "subject" with our key, this signer already generates asn1 notation
          Signature signature = Signature.getInstance("SHA256withECDSA");
          signature.initSign(keys.getPrivate());
          signature.update(subject.getBytes(StandardCharsets.UTF_8));
          byte[] signed = signature.sign();

          // create a certificate request with our public key and our signed "subject"
          CertificateRequest cReq = new CertificateRequest(keys.getPublic(), signed);

          // ask fulcio for a signing cert
          CertificateResponse cResp = c.SigningCert(cReq, token);

          // some pretty basic assertions
          Assert.assertTrue(cResp.getCertPath().getCertificates().size() > 0);
          Assert.assertTrue(cResp.getSct().length > 0);
        }
      }
    }
  }
}
