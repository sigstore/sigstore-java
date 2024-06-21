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
package dev.sigstore;

import dev.sigstore.fulcio.client.FulcioCertificateMatcher;
import dev.sigstore.fulcio.client.ImmutableFulcioCertificateMatcher;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Predicate;
import org.immutables.value.Value.Immutable;

@Immutable(singleton = true)
public interface VerificationOptions {

  /** An allow list of certificate identities to match with. */
  List<CertificateMatcher> getCertificateMatchers();

  /**
   * An interface for allowing matching of certificates. Use {@link #fulcio()} to instantiate the
   * default {@link FulcioCertificateMatcher} implementation. Custom implementations may throw
   * {@link UncheckedCertificateException} if an error occurs processing the certificate on calls to
   * {@link #test(X509Certificate)}. Any other runtime exception will not be handled.
   */
  interface CertificateMatcher extends Predicate<X509Certificate> {
    @Override
    boolean test(X509Certificate certificate) throws UncheckedCertificateException;

    static ImmutableFulcioCertificateMatcher.Builder fulcio() {
      return ImmutableFulcioCertificateMatcher.builder();
    }
  }

  /** Exceptions thrown by implementations of {@link CertificateMatcher#test(X509Certificate)} */
  class UncheckedCertificateException extends RuntimeException {
    public UncheckedCertificateException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  static ImmutableVerificationOptions.Builder builder() {
    return ImmutableVerificationOptions.builder();
  }

  static VerificationOptions empty() {
    return ImmutableVerificationOptions.of();
  }
}
