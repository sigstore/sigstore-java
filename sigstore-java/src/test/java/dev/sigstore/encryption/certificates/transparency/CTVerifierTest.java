/*
 * Copyright 2022 The Sigstore Authors.
 * Copyright 2015 The Android Open Source Project.
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
package dev.sigstore.encryption.certificates.transparency;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import dev.sigstore.encryption.Keys;
import dev.sigstore.encryption.certificates.Certificates;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CTVerifierTest {
  private X509Certificate ca;
  private X509Certificate cert;
  private X509Certificate certEmbedded;
  private CTVerifier ctVerifier;

  @BeforeEach
  public void setUp() throws Exception {
    ca =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toByteArray(
                    Resources.getResource(
                        "dev/sigstore/samples/certificatetransparency/ca-cert.pem")));
    cert =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toByteArray(
                    Resources.getResource(
                        "dev/sigstore/samples/certificatetransparency/cert.pem")));
    certEmbedded =
        (X509Certificate)
            Certificates.fromPem(
                Resources.toByteArray(
                    Resources.getResource(
                        "dev/sigstore/samples/certificatetransparency/cert-ct-embedded.pem")));

    // a little hacky pem parser, but lightweight
    String keyData =
        Resources.toString(
                Resources.getResource(
                    "dev/sigstore/samples/certificatetransparency/ct-server-key-public.pem"),
                StandardCharsets.UTF_8)
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
    PublicKey key = Keys.parseEcdsa(Base64.decode(keyData));

    final CTLogInfo log = new CTLogInfo(key, "Test Log", "foo");
    CTLogStore store =
        new CTLogStore() {
          @Override
          public CTLogInfo getKnownLog(byte[] logId) {
            if (Arrays.equals(logId, log.getID())) {
              return log;
            } else {
              return null;
            }
          }
        };

    ctVerifier = new CTVerifier(store);
  }

  @Test
  public void test_verifySignedCertificateTimestamps_withEmbeddedExtension() throws Exception {
    List<X509Certificate> chain = ImmutableList.of(certEmbedded, ca);

    CTVerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
    Assertions.assertEquals(1, result.getValidSCTs().size());
    Assertions.assertEquals(0, result.getInvalidSCTs().size());
  }

  @Test
  public void test_verifySignedCertificateTimestamps_withoutTimestamp() throws Exception {
    List<X509Certificate> chain = ImmutableList.of(cert, ca);

    CTVerificationResult result = ctVerifier.verifySignedCertificateTimestamps(chain, null, null);
    Assertions.assertEquals(0, result.getValidSCTs().size());
    Assertions.assertEquals(0, result.getInvalidSCTs().size());
  }
}
