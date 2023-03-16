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

import dev.sigstore.KeylessSigner;
import dev.sigstore.encryption.certificates.Certificates;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "sign", description = "sign an artifacts")
public class Sign implements Callable<Integer> {

  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to sign")
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

  @Override
  public Integer call() throws Exception {
    var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
    var signingResult = signer.signFile(artifact);
    Files.write(signatureFile, signingResult.getSignature());
    Files.write(certificateFile, Certificates.toPemBytes(signingResult.getCertPath()));
    return 0;
  }
}
