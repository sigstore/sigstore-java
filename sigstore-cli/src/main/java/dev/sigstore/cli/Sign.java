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
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.SigstoreTufClient;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "sign",
    aliases = {"sign-bundle"},
    description = "sign an artifacts")
public class Sign implements Callable<Integer> {

  @Parameters(arity = "1", paramLabel = "<artifact>", description = "artifact to sign")
  Path artifact;

  @ArgGroup(multiplicity = "1", exclusive = true)
  SignatureFiles signatureFiles;

  @ArgGroup(multiplicity = "0..1", exclusive = true)
  Verify.Target target;

  static class Target {
    @Option(
        names = {"--staging"},
        description = "test against staging",
        required = false,
        defaultValue = "false")
    Boolean staging;

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

  @Option(
      names = {"--identity-token"},
      description = "the OIDC identity token to use",
      required = false)
  String identityToken;

  @Override
  public Integer call() throws Exception {
    KeylessSigner.Builder signerBuilder;
    if (target == null) {
      signerBuilder = new KeylessSigner.Builder().sigstorePublicDefaults();
    } else if (target.staging) {
      signerBuilder = new KeylessSigner.Builder().sigstoreStagingDefaults();
    } else if (target.publicGoodWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .usePublicGoodInstance()
              .tufMirror(
                  new URL(target.publicGoodWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.PUBLIC_GOOD_ROOT_RESOURCE));
      signerBuilder =
          KeylessSigner.builder()
              .sigstorePublicDefaults()
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder));
    } else if (target.stagingWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .useStagingInstance()
              .tufMirror(
                  new URL(target.stagingWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.STAGING_ROOT_RESOURCE));
      signerBuilder =
          KeylessSigner.builder()
              .sigstoreStagingDefaults()
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder));
    } else {
      throw new IllegalStateException("Unable to initialize signer");
    }
    if (identityToken != null) {
      // If we've explicitly provided an identity token, customize the signer to only use the token
      // string OIDC client.
      signerBuilder.oidcClients(OidcClients.of(new TokenStringOidcClient(identityToken)));
    }
    var signer = signerBuilder.build();
    var bundle = signer.signFile(artifact);
    if (signatureFiles.sigAndCert != null) {
      Files.write(
          signatureFiles.sigAndCert.signatureFile,
          Base64.getEncoder().encode(bundle.getMessageSignature().get().getSignature()));
      Files.write(
          signatureFiles.sigAndCert.certificateFile, Certificates.toPemBytes(bundle.getCertPath()));
    } else {
      Files.write(signatureFiles.bundleFile, bundle.toJson().getBytes(StandardCharsets.UTF_8));
    }
    return 0;
  }
}
