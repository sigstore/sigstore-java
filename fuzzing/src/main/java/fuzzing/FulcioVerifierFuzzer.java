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
package fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import dev.sigstore.fulcio.client.FulcioVerificationException;
import dev.sigstore.fulcio.client.FulcioVerifier;
import dev.sigstore.fulcio.client.SigningCertificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import util.Tuf;

public class FulcioVerifierFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] intArray = data.consumeInts(data.consumeInt(1, 10));

      var cas = Tuf.certificateAuthoritiesFrom(data);
      var ctLogs = Tuf.transparencyLogsFrom(data);

      byte[] byteArray = data.consumeRemainingAsBytes();
      List<Certificate> certList = new ArrayList<Certificate>();
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      certList.add(cf.generateCertificate(new ByteArrayInputStream(byteArray)));
      certList.add(cf.generateCertificate(new ByteArrayInputStream(byteArray)));

      SigningCertificate sc = SigningCertificate.from(cf.generateCertPath(certList));
      FulcioVerifier fv = FulcioVerifier.newFulcioVerifier(cas, ctLogs);

      for (int choice : intArray) {
        switch (choice % 4) {
          case 0:
            sc.getCertificates();
            break;
          case 1:
            sc.getLeafCertificate();
            break;
          case 3:
            fv.verifySigningCertificate(sc);
            break;
        }
      }
    } catch (CertificateException
        | FulcioVerificationException
        | InvalidKeySpecException
        | NoSuchAlgorithmException
        | InvalidAlgorithmParameterException
        | IOException e) {
      // Known exception
    }
  }
}
