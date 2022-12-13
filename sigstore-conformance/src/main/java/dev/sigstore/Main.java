package dev.sigstore;

import com.google.common.hash.Hashing;
import dev.sigstore.oidc.client.GithubActionsOidcClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static com.google.common.io.Files.asByteSource;
import static dev.sigstore.encryption.certificates.Certificates.toPemString;

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
    final private String[] args;

    public Arguments(String[] args) {
      this.index = 0;
      this.args = args;
    }

    public String getNextArgument() {
      if (index >= args.length) {
        final var errorMsg = String.format(
          "Insufficient arguments; amount=%d, requested=%d",
          args.length, index);
        throw new IllegalArgumentException(errorMsg);
      }
      return args[index++];
    }

    public void expectNextArgument(String expectedArg) {
      final var nextArg = getNextArgument();
      if (!expectedArg.equals(nextArg)) {
        final var errorMsg = String.format(
          "Found unexpected argument; expected=\"%s\", found=\"%s\"",
          expectedArg, nextArg);
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
      KeylessSigner.builder().sigstorePublicDefaults().oidcClient(
        GithubActionsOidcClient.builder().build()
      ).build();
    final var result = signer.signFile(args.artifact);
    Files.write(args.signature, result.getSignature());
    final var pemBytes = toPemString(result.getCertPath()).getBytes();
    Files.write(args.certificate, pemBytes);
  }

  private static class VerifyArguments {
    public Path signature;
    public Path certificate;
    public String certificateIdentity;
    public String certificateOidcIssuer;
    public Path artifact;
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
    final var verifier =
      KeylessVerifier.builder().sigstorePublicDefaults().build();
    final var artifactByteSource = asByteSource(args.artifact.toFile());
    final byte[] artifactDigest =
      artifactByteSource.hash(Hashing.sha256()).asBytes();
    verifier.verifyOnline(
      artifactDigest,
      Files.readAllBytes(args.certificate),
      Files.readAllBytes(args.signature));
  }
}
