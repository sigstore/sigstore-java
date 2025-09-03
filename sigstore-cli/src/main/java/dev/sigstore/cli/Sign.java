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
import dev.sigstore.SigningConfigProvider;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.TokenStringOidcClient;
import dev.sigstore.tuf.RootProvider;
import dev.sigstore.tuf.SigstoreTufClient;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

  @Option(
      names = {"--bundle"},
      description = "path to bundle file",
      required = true)
  Path bundleFile;

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
      names = {"--signing-config"},
      description = "a custom signing config",
      required = false)
  Path signingConfig;

  @Option(
      names = {"--identity-token"},
      description = "the OIDC identity token to use",
      required = false)
  String identityToken;

  @Option(
      names = {"--working-directory"},
      description = "the working directory",
      required = false)
  Path workingDirectory;

  @Override
  public Integer call() throws Exception {
    if (workingDirectory != null) {
      artifact = workingDirectory.resolve(artifact);
      bundleFile = workingDirectory.resolve(bundleFile);
      if (signingConfig != null) {
        signingConfig = workingDirectory.resolve(signingConfig);
      }
      if (target != null && target.trustedRoot != null) {
        target.trustedRoot = workingDirectory.resolve(target.trustedRoot);
      }
    }
    KeylessSigner.Builder signerBuilder;
    if (target == null) {
      signerBuilder = new KeylessSigner.Builder().sigstorePublicDefaults().enableRekorV2(true);
    } else if ((target.trustedRoot != null && signingConfig == null)
        || (target.trustedRoot == null && signingConfig != null)) {
      throw new IllegalArgumentException(
          "Trusted root and signing config are both required if one is provided");
    } else if (target.trustedRoot != null && signingConfig != null) {
      signerBuilder =
          new KeylessSigner.Builder()
              .sigstoreStagingDefaults()
              .enableRekorV2(true)
              .trustedRootProvider(TrustedRootProvider.from(target.trustedRoot))
              .signingConfigProvider(SigningConfigProvider.from(signingConfig));
    } else if (target.staging) {
      signerBuilder = new KeylessSigner.Builder().sigstoreStagingDefaults().enableRekorV2(true);
    } else if (target.publicGoodWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .usePublicGoodInstance()
              .tufMirror(
                  URI.create(target.publicGoodWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.PUBLIC_GOOD_ROOT_RESOURCE));
      signerBuilder =
          KeylessSigner.builder()
              .sigstorePublicDefaults()
              .enableRekorV2(true)
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder));
    } else if (target.stagingWithTufUrlOverride != null) {
      var tufClientBuilder =
          SigstoreTufClient.builder()
              .useStagingInstance()
              .tufMirror(
                  URI.create(target.stagingWithTufUrlOverride),
                  RootProvider.fromResource(SigstoreTufClient.STAGING_ROOT_RESOURCE));
      signerBuilder =
          KeylessSigner.builder()
              .sigstoreStagingDefaults()
              .enableRekorV2(true)
              .trustedRootProvider(TrustedRootProvider.from(tufClientBuilder));
    } else {
      throw new IllegalStateException("Unable to initialize signer");
    }
    if (identityToken != null) {
      // If we've explicitly provided an identity token, customize the signer to only use the token
      // string OIDC client.
      signerBuilder.forceCredentialProviders(
          OidcClients.of(TokenStringOidcClient.from(identityToken)));
    }
    var signer = signerBuilder.build();
    var bundle = signer.signFile(artifact);
    Files.write(bundleFile, bundle.toJson().getBytes(StandardCharsets.UTF_8));
    return 0;
  }
}
