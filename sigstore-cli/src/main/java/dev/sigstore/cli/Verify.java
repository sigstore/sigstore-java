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
import dev.sigstore.KeylessSignature;
import dev.sigstore.KeylessVerificationRequest;
import dev.sigstore.KeylessVerificationRequest.CertificateIdentity;
import dev.sigstore.KeylessVerificationRequest.VerificationOptions;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.encryption.certificates.Certificates;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "verify", description = "verify an artifact")
public class Verify implements Callable<Integer> {
  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to verify")
  Path artifact;

  @Option(
      names = {"--signature"},
      description = "path to signature file",
      required = true)
  Path signatureFile;

  @Option(
      names = {"--certificate"},
      description = "path to certificate file",
      required = true)
  Path certificateFile;

  @Option(
      names = {"--certificate-identity"},
      description = "subject alternative name in certificate")
  private String certificateSan;

  @Option(
      names = {"--certificate-oidc-issuer"},
      description = "sigstore issuer in certificate")
  private String certificateIssuer;

  @Override
  public Integer call() throws Exception {
    byte[] digest = asByteSource(artifact.toFile()).hash(Hashing.sha256()).asBytes();
    byte[] signature = Files.readAllBytes(signatureFile);
    CertPath certPath = Certificates.fromPemChain(Files.readAllBytes(certificateFile));

    var verifier = new KeylessVerifier.Builder().sigstorePublicDefaults().build();
    verifier.verify(
        artifact,
        KeylessVerificationRequest.builder()
            .keylessSignature(
                KeylessSignature.builder()
                    .signature(signature)
                    .certPath(certPath)
                    .digest(digest)
                    .build())
            .verificationOptions(
                VerificationOptions.builder()
                    .isOnline(true)
                    .addCertificateIdentities(
                        CertificateIdentity.builder()
                            .issuer(certificateIssuer)
                            .subjectAlternativeName(certificateSan)
                            .build())
                    .build())
            .build());
    return 0;
  }
}
