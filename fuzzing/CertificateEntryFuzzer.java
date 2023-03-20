/*
 * Copyright 2023 The Sigstore Authors.
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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import dev.sigstore.encryption.certificates.transparency.CertificateEntry;
import dev.sigstore.encryption.certificates.transparency.SerializationException;

public class CertificateEntryFuzzer{
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      byte[] byteArray = data.consumeRemainingAsBytes();
      byte[] byteArray1 = Arrays.copyOfRange(byteArray, 0, byteArray.length/2);
      byte[] byteArray2 = Arrays.copyOfRange(byteArray, byteArray.length/2, byteArray.length);

      X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteArray));
      X509Certificate cert1 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteArray1));
      X509Certificate cert2 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteArray2));

      CertificateEntry ce1 = CertificateEntry.createForPrecertificate(byteArray1, byteArray2);
      CertificateEntry ce2 = CertificateEntry.createForPrecertificate(cert1, cert2);
      CertificateEntry ce3 = CertificateEntry.createForX509Certificate(byteArray);
      CertificateEntry ce4 = CertificateEntry.createForX509Certificate(cert);

      ce1.encode(new ByteArrayOutputStream());
      ce2.encode(new ByteArrayOutputStream());
      ce3.encode(new ByteArrayOutputStream());
      ce4.encode(new ByteArrayOutputStream());
    } catch (CertificateException e) {
    } catch (SerializationException e) {
    }
  }
}
