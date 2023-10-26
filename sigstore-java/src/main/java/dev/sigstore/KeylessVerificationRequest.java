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

import java.util.List;
import java.util.Map;
import org.immutables.value.Value.Default;
import org.immutables.value.Value.Immutable;

@Immutable
public interface KeylessVerificationRequest {
  KeylessSignature getKeylessSignature();

  @Default
  default VerificationOptions getVerificationOptions() {
    return VerificationOptions.builder().alwaysUseRemoteRekorEntry(false).build();
  }

  @Immutable
  interface VerificationOptions {

    /**
     * Connect to rekor to obtain a rekor entry for verification. This will ignore the provided
     * rekor entry in a {@link KeylessSignature}. Verifier may still connect to Rekor to obtain an
     * entry if no {@link KeylessSignature#getEntry()} is empty.
     */
    boolean alwaysUseRemoteRekorEntry();

    List<CertificateIdentity> getCertificateIdentities();

    static ImmutableVerificationOptions.Builder builder() {
      return ImmutableVerificationOptions.builder();
    }
  }

  @Immutable
  interface CertificateIdentity {
    String getIssuer();

    String getSubjectAlternativeName();

    Map<String, String> getOther();

    static ImmutableCertificateIdentity.Builder builder() {
      return ImmutableCertificateIdentity.builder();
    }
  }

  static ImmutableKeylessVerificationRequest.Builder builder() {
    return ImmutableKeylessVerificationRequest.builder();
  }
}
