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

import dev.sigstore.fulcio.v2.CertificateChain;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/** A client to communicate with a fulcio service instance. */
public interface FulcioClient {
  URI PUBLIC_GOOD_URI = URI.create("https://fulcio.sigstore.dev");
  URI STAGING_URI = URI.create("https://fulcio.sigstage.dev");

  CertPath signingCertificate(CertificateRequest request)
      throws InterruptedException, CertificateException;

  static CertPath decodeCerts(CertificateChain certChain) throws CertificateException {
    var certificateFactory = CertificateFactory.getInstance("X.509");
    var certs = new ArrayList<X509Certificate>();
    if (certChain.getCertificatesCount() == 0) {
      throw new CertificateParsingException(
          "no valid PEM certificates were found in response from Fulcio");
    }
    for (var cert : certChain.getCertificatesList()) {
      certs.add(
          (X509Certificate)
              certificateFactory.generateCertificate(
                  new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8))));
    }
    return certificateFactory.generateCertPath(certs);
  }
}
