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
package dev.sigstore.encryption.certificates;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class Certificates {

  /** Convert a certificate to a PEM encoded certificate. */
  public static String toPemString(Certificate cert) throws IOException {
    var certWriter = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(certWriter)) {
      pemWriter.writeObject(cert);
      pemWriter.flush();
    }
    return certWriter.toString();
  }

  /** Convert a certificate to a PEM encoded certificate. */
  public static byte[] toPemBytes(Certificate cert) throws IOException {
    return toPemString(cert).getBytes(StandardCharsets.UTF_8);
  }
}
