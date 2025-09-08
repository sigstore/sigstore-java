/*
 * Copyright 2024 The Sigstore Authors.
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
package dev.sigstore.rekor.client;

import dev.sigstore.KeylessVerificationException;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.trustroot.Service;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.TransparencyLog;
import dev.sigstore.tuf.SigstoreTufClient;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Compat fetcher of rekor entries for incomplete offline signature separates. Only useful to
 * construct a complete {@link dev.sigstore.bundle.Bundle} from signature, artifact and certpath
 * with no rekor entry provided.
 */
public class RekorEntryFetcher {
  // a client per remote trusted log
  private final List<RekorClient> rekorClients;

  public static RekorEntryFetcher sigstoreStaging() throws SigstoreConfigurationException {
    var sigstoreTufClientBuilder = SigstoreTufClient.builder().useStagingInstance();
    return fromTrustedRoot(TrustedRootProvider.from(sigstoreTufClientBuilder));
  }

  public static RekorEntryFetcher sigstorePublicGood() throws SigstoreConfigurationException {
    var sigstoreTufClientBuilder = SigstoreTufClient.builder().usePublicGoodInstance();
    return fromTrustedRoot(TrustedRootProvider.from(sigstoreTufClientBuilder));
  }

  public static RekorEntryFetcher fromTrustedRoot(Path trustedRoot)
      throws SigstoreConfigurationException {
    return fromTrustedRoot(TrustedRootProvider.from(trustedRoot));
  }

  public static RekorEntryFetcher fromTrustedRoot(TrustedRootProvider trustedRootProvider)
      throws SigstoreConfigurationException {
    var trustedRoot = trustedRootProvider.get();
    var rekorClients =
        trustedRoot.getTLogs().stream()
            .map(TransparencyLog::getBaseUrl)
            .distinct()
            .map(uri -> RekorClientHttp.builder().setService(Service.of(uri, 1)).build())
            .collect(Collectors.<RekorClient>toList());
    return new RekorEntryFetcher(rekorClients);
  }

  public RekorEntryFetcher(List<RekorClient> rekorClients) {
    this.rekorClients = rekorClients;
  }

  public RekorEntry getEntryFromRekor(
      byte[] artifactDigest, X509Certificate leafCert, byte[] signature)
      throws KeylessVerificationException {
    // rebuild the hashedRekord so we can query the log for it
    HashedRekordRequest hashedRekordRequest;
    try {
      hashedRekordRequest =
          HashedRekordRequest.newHashedRekordRequest(
              artifactDigest, Certificates.toPemBytes(leafCert), signature);
    } catch (IOException e) {
      throw new KeylessVerificationException(
          "Could not convert certificate to PEM when recreating hashedrekord", e);
    }
    Optional<RekorEntry> rekorEntry;

    // attempt to grab a valid rekord from all known rekor instances
    try {
      for (var rekorClient : rekorClients) {
        rekorEntry = rekorClient.getEntry(hashedRekordRequest);
        if (rekorEntry.isPresent()) {
          var entryTime = Date.from(rekorEntry.get().getIntegratedTimeInstant());
          try {
            // only return this entry if it's valid for the certificate
            leafCert.checkValidity(entryTime);
          } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            continue;
          }
          return rekorEntry.get();
        }
      }
    } catch (IOException | RekorParseException e) {
      throw new KeylessVerificationException("Could not retrieve rekor entry", e);
    }
    throw new KeylessVerificationException("No valid rekor entry was not found in any known logs");
  }
}
