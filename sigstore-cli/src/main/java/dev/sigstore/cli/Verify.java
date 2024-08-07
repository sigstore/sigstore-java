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
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.VerificationOptions;
import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.Bundle.HashAlgorithm;
import dev.sigstore.bundle.Bundle.MessageSignature;
import dev.sigstore.bundle.ImmutableBundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.rekor.client.RekorEntryFetcher;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.SigstoreTufClient;
import java.net.URL;
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

    @Option(
        names = {"--public-good-with-tuf-url-override"},
        description = "use public good with a tuf remote repository override",
        required = false)
    String publicGoodWithTufUrlOverride;

    @Option(
        names = {"--staging-with-tuf-url-override"},
        description = "use staging with a tuf remote repository override",
        required = false)
    String stagingWithTufUrlOverride;
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
      bundle = Bundle.from(signatureFiles.bundleFile, StandardCharsets.UTF_8);
    }

    var verificationOptionsBuilder = VerificationOptions.builder();
    if (policy != null) {
      verificationOptionsBuilder.addCertificateMatchers(
          CertificateMatcher.fulcio()
              .issuer(StringMatcher.string(policy.certificateIssuer))
              .subjectAlternativeName(StringMatcher.string(policy.certificateSan))
              .build());
    }
    var verificationOptions = verificationOptionsBuilder.build();

    KeylessVerifier verifier;
    if (target == null) {
      verifier = new KeylessVerifier.Builder().sigstorePublicDefaults().build();
    } else if (target.staging) {
      verifier = new KeylessVerifier.Builder().sigstoreStagingDefaults().build();
    } else if (target.trustedRoot != null) {
      verifier =
          new KeylessVerifier.Builder()
              .trustedRootProvider(TrustedRootProvider.from(target.trustedRoot))
              .build();
    } else if (target.publicGoodWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .usePublicGoodInstance()
              .tufMirror(
                  new URL(target.publicGoodWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.PUBLIC_GOOD_ROOT_RESOURCE));
      verifier =
          KeylessVerifier.builder()
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder))
              .build();
    } else if (target.stagingWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .useStagingInstance()
              .tufMirror(
                  new URL(target.stagingWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.STAGING_ROOT_RESOURCE));
      verifier =
          KeylessVerifier.builder()
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder))
              .build();
    } else {
      throw new IllegalStateException("Unable to initialize verifier");
    }
    verifier.verify(artifact, bundle, verificationOptions);
    return 0;
  }
}
