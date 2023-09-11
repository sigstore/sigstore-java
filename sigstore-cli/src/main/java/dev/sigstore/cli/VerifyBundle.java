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

import static com.google.common.io.Files.newReader;

import dev.sigstore.KeylessSignature;
import dev.sigstore.KeylessVerificationRequest;
import dev.sigstore.KeylessVerificationRequest.CertificateIdentity;
import dev.sigstore.KeylessVerificationRequest.VerificationOptions;
import dev.sigstore.KeylessVerifier2;
import dev.sigstore.bundle.BundleFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "verify-bundle", description = "verify an artifact using a sigstore bundle")
public class VerifyBundle implements Callable<Integer> {
  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to verify")
  Path artifact;

  @Option(
      names = {"--bundle"},
      description = "path to bundle file",
      required = true)
  Path bundleFile;

  @ArgGroup(multiplicity = "0..1", exclusive = false)
  Policy policy;

  @Override
  public Integer call() throws Exception {
    KeylessSignature keylessSignature =
        BundleFactory.readBundle(newReader(bundleFile.toFile(), StandardCharsets.UTF_8));

    var verificationOptionsBuilder = VerificationOptions.builder();
    if (policy != null) {
      verificationOptionsBuilder.addCertificateIdentities(
          CertificateIdentity.builder()
              .issuer(policy.certificateIssuer)
              .subjectAlternativeName(policy.certificateSan)
              .build());
    }
    var verificationOptions = verificationOptionsBuilder.isOnline(true).build();

    var verifier = new KeylessVerifier2.Builder().sigstorePublicDefaults().build();
    verifier.verify(
        artifact,
        KeylessVerificationRequest.builder()
            .keylessSignature(keylessSignature)
            .verificationOptions(verificationOptions)
            .build());
    return 0;
  }
}
