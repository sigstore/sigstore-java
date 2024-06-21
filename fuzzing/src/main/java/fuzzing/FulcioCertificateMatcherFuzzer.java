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
import dev.sigstore.VerificationOptions.UncheckedCertificateException;
import dev.sigstore.fulcio.client.FulcioCertificateMatcher;
import dev.sigstore.fulcio.client.ImmutableFulcioCertificateMatcher;
import dev.sigstore.strings.StringMatcher;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class FulcioCertificateMatcherFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] byteArray = data.consumeRemainingAsBytes();
    String san = new String(byteArray, Charset.defaultCharset());
    String issuer = new String(byteArray, Charset.defaultCharset());

    X509Certificate certificate;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteArray));
    } catch (Exception e) {
      // Skipping this iteration if exceptions thrown during certificate creation
      return;
    }

    try {
      FulcioCertificateMatcher matcher =
          ImmutableFulcioCertificateMatcher.builder()
              .subjectAlternativeName(StringMatcher.string(san))
              .issuer(StringMatcher.string(issuer))
              .build();

      matcher.test(certificate);
    } catch (UncheckedCertificateException e) {
      // Known exception
    }
  }
}
