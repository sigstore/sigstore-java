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
import dev.sigstore.bundle.BundleFactory;
import dev.sigstore.encryption.certificates.Certificates;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "sign", description = "sign an artifacts")
public class Sign implements Callable<Integer> {

  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to sign")
  Path artifact;

  @ArgGroup(multiplicity = "1", exclusive = true)
  SignatureFiles signatureFiles;

  @Override
  public Integer call() throws Exception {
    var signer = KeylessSigner.builder().sigstorePublicDefaults().build();
    var signingResult = signer.signFile(artifact);
    if (signatureFiles.sigAndCert != null) {
      Files.write(signatureFiles.sigAndCert.signatureFile, signingResult.getSignature());
      Files.write(
          signatureFiles.sigAndCert.certificateFile,
          Certificates.toPemBytes(signingResult.getCertPath()));
    } else {
      Files.write(
          signatureFiles.bundleFile,
          BundleFactory.createBundle(signingResult).getBytes(StandardCharsets.UTF_8));
    }
    return 0;
  }
}
