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
package dev.sigstore.cli;

import static com.google.common.io.Files.asByteSource;

import com.google.common.hash.Hashing;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.VerificationOptions;
import dev.sigstore.VerificationOptions.CertificateIdentity;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.Bundle.HashAlgorithm;
import dev.sigstore.bundle.Bundle.MessageSignature;
import dev.sigstore.bundle.ImmutableBundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.rekor.client.RekorEntryFetcher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.util.Base64;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "verify",
    aliases = {"verify-bundle"},
    description = "verify an artifact")
public class Verify implements Callable<Integer> {
  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to verify")
  Path artifact;

  @ArgGroup(multiplicity = "1", exclusive = true)
  SignatureFiles signatureFiles;

  @ArgGroup(multiplicity = "0..1", exclusive = false)
  Policy policy;

  @ArgGroup(multiplicity = "0..1", exclusive = true)
  Target target;

  /**
   * Chose one trusted root provider target, (staging or prod or custom trusted_root), default is
   * prod.
   */
  static class Target {
    @Option(
        names = {"--staging"},
        description = "test against staging",
        required = false,
        defaultValue = "false")
    Boolean staging;

    @Option(
        names = {"--trusted-root"},
        description = "an alternative to the TUF managed sigstore public good trusted root",
        required = false)
    Path trustedRoot;
  }

  static class Policy {
    @Option(
        names = {"--certificate-identity"},
        description = "subject alternative name in certificate",
        required = true)
    String certificateSan;

    @Option(
        names = {"--certificate-oidc-issuer"},
        description = "sigstore issuer in certificate",
        required = true)
    String certificateIssuer;
  }

  @Override
  public Integer call() throws Exception {
    byte[] digest = asByteSource(artifact.toFile()).hash(Hashing.sha256()).asBytes();

    Bundle bundle;
    if (signatureFiles.sigAndCert != null) {
      byte[] signature =
          Base64.getMimeDecoder()
              .decode(Files.readAllBytes(signatureFiles.sigAndCert.signatureFile));
      CertPath certPath =
          Certificates.fromPemChain(Files.readAllBytes(signatureFiles.sigAndCert.certificateFile));
      RekorEntryFetcher fetcher =
          target == null
              ? RekorEntryFetcher.sigstorePublicGood()
              : target.staging
                  ? RekorEntryFetcher.sigstoreStaging()
                  : RekorEntryFetcher.fromTrustedRoot(target.trustedRoot);
      bundle =
          ImmutableBundle.builder()
              .messageSignature(MessageSignature.of(HashAlgorithm.SHA2_256, digest, signature))
              .certPath(certPath)
              .addEntries(
                  fetcher.getEntryFromRekor(digest, Certificates.getLeaf(certPath), signature))
              .build();
    } else {
      bundle =
          Bundle.from(Files.newBufferedReader(signatureFiles.bundleFile, StandardCharsets.UTF_8));
    }

    var verificationOptionsBuilder = VerificationOptions.builder();
    if (policy != null) {
      verificationOptionsBuilder.addCertificateIdentities(
          CertificateIdentity.builder()
              .issuer(policy.certificateIssuer)
              .subjectAlternativeName(policy.certificateSan)
              .build());
    }
    var verificationOptions = verificationOptionsBuilder.build();

    var verifier =
        target == null
            ? new KeylessVerifier.Builder().sigstorePublicDefaults().build()
            : target.staging
                ? new KeylessVerifier.Builder().sigstoreStagingDefaults().build()
                : new KeylessVerifier.Builder().fromTrustedRoot(target.trustedRoot).build();
    verifier.verify(artifact, bundle, verificationOptions);
    return 0;
  }
}
