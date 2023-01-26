/*
 * Copyright 2022 The Sigstore Authors.
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
package dev.sigstore.conformance;

import static dev.sigstore.encryption.certificates.Certificates.toPemString;

import dev.sigstore.KeylessSigner;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

public class Main {
  private static final String SIGN_COMMAND = "sign";
  private static final String VERIFY_COMMAND = "verify";
  private static final String SIGNATURE_FLAG = "--signature";
  private static final String CERTIFICATE_FLAG = "--certificate";
  private static final String CERTIFICATE_IDENTITY_FLAG = "--certificate-identity";
  private static final String CERTIFICATE_OIDC_ISSUER_FLAG = "--certificate-oidc-issuer";

  public static void main(String[] args) throws Exception {
    Arguments a = new Arguments(args);
    final var action = a.getNextArgument();
    if (action.equals(SIGN_COMMAND)) {
      final SignArguments signArgs = parseSignArguments(a);
      executeSign(signArgs);
    } else if (action.equals(VERIFY_COMMAND)) {
      final VerifyArguments verifyArgs = parseVerifyArguments(a);
      executeVerify(verifyArgs);
    } else {
      throw new IllegalArgumentException("Unrecognized action: " + action);
    }
  }

  private static class Arguments {
    private int index;
    private final String[] args;

    public Arguments(String[] args) {
      this.index = 0;
      this.args = args;
    }

    public String getNextArgument() {
      if (index >= args.length) {
        final var errorMsg =
            String.format(
                Locale.ROOT, "Insufficient arguments; amount=%d, requested=%d", args.length, index);
        throw new IllegalArgumentException(errorMsg);
      }
      return args[index++];
    }

    public void expectNextArgument(String expectedArg) {
      final var nextArg = getNextArgument();
      if (!expectedArg.equals(nextArg)) {
        final var errorMsg =
            String.format(
                Locale.ROOT,
                "Found unexpected argument; expected=\"%s\", found=\"%s\"",
                expectedArg,
                nextArg);
        throw new IllegalArgumentException(errorMsg);
      }
    }
  }

  private static class SignArguments {
    public Path signature;
    public Path certificate;
    public Path artifact;
  }

  private static SignArguments parseSignArguments(Arguments args) {
    final var signArgs = new SignArguments();
    args.expectNextArgument(SIGNATURE_FLAG);
    signArgs.signature = Paths.get(args.getNextArgument());
    args.expectNextArgument(CERTIFICATE_FLAG);
    signArgs.certificate = Paths.get(args.getNextArgument());
    signArgs.artifact = Paths.get(args.getNextArgument());
    return signArgs;
  }

  private static void executeSign(SignArguments args) throws Exception {
    final var signer =
        KeylessSigner.builder()
            .sigstorePublicDefaults()
            .oidcClient(GithubActionsOidcClient.builder().build())
            .build();
    final var result = signer.signFile(args.artifact);
    Files.write(args.signature, result.getSignature());
    final var pemBytes = toPemString(result.getCertPath()).getBytes(StandardCharsets.UTF_8);
    Files.write(args.certificate, pemBytes);
  }

  private static class VerifyArguments {
    public Path signature;
    public Path certificate;
    public Path artifact;

    @SuppressWarnings("unused") // remove when verifier actually verifies these
    public String certificateIdentity;

    @SuppressWarnings("unused") // remove when verifier actually verifies these
    public String certificateOidcIssuer;
  }

  private static VerifyArguments parseVerifyArguments(Arguments args) {
    final var verifyArgs = new VerifyArguments();
    args.expectNextArgument(SIGNATURE_FLAG);
    verifyArgs.signature = Paths.get(args.getNextArgument());
    args.expectNextArgument(CERTIFICATE_FLAG);
    verifyArgs.certificate = Paths.get(args.getNextArgument());
    args.expectNextArgument(CERTIFICATE_IDENTITY_FLAG);
    verifyArgs.certificateIdentity = args.getNextArgument();
    args.expectNextArgument(CERTIFICATE_OIDC_ISSUER_FLAG);
    verifyArgs.certificateOidcIssuer = args.getNextArgument();
    verifyArgs.artifact = Paths.get(args.getNextArgument());
    return verifyArgs;
  }

  private static void executeVerify(VerifyArguments args) throws Exception {
    final var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    final byte[] artifactDigest = sha256(args.artifact);
    verifier.verifyOnline(
        artifactDigest, Files.readAllBytes(args.certificate), Files.readAllBytes(args.signature));
  }

  private static byte[] sha256(Path path) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream in = Files.newInputStream(path)) {
      byte[] buffer = new byte[1024];
      int count;
      while ((count = in.read(buffer)) > 0) {
        digest.update(buffer, 0, count);
      }
    }
    return digest.digest();
  }
}
