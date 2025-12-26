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
import com.google.common.io.BaseEncoding;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.VerificationOptions;
import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.SigstoreTufClient;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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

  private static final String SHA256_PREFIX = "sha256:";

  @Parameters(
      arity = "1",
      paramLabel = "<artifact>",
      description = "an artifact path or artifact hash (sha256:abc...) to verify")
  String artifact;

  @Option(
      names = {"--bundle"},
      description = "path to bundle file",
      required = true)
  Path bundleFile;

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

  @Option(
      names = {"--working-directory"},
      description = "the working directory",
      required = false)
  Path workingDirectory;

  @Override
  public Integer call() throws Exception {
    byte[] digest;
    if (artifact.startsWith(SHA256_PREFIX)) {
      digest =
          BaseEncoding.base16().ignoreCase().decode(artifact.substring(SHA256_PREFIX.length()));
    } else {
      if (workingDirectory != null) {
        artifact = workingDirectory.resolve(artifact).toString();
      }
      digest = asByteSource(Path.of(artifact).toFile()).hash(Hashing.sha256()).asBytes();
    }

    if (workingDirectory != null) {
      bundleFile = workingDirectory.resolve(bundleFile);
      if (target != null && target.trustedRoot != null) {
        target.trustedRoot = workingDirectory.resolve(target.trustedRoot);
      }
    }

    Bundle bundle = Bundle.from(bundleFile, StandardCharsets.UTF_8);

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
                  URI.create(target.publicGoodWithTufUrlOverride),
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
                  URI.create(target.stagingWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.STAGING_ROOT_RESOURCE));
      verifier =
          KeylessVerifier.builder()
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder))
              .build();
    } else {
      throw new IllegalStateException("Unable to initialize verifier");
    }
    if (artifact.startsWith(SHA256_PREFIX)) {
      verifier.verify(digest, bundle, verificationOptions);
    } else {
      verifier.verify(Path.of(artifact), bundle, verificationOptions);
    }
    return 0;
  }
}
