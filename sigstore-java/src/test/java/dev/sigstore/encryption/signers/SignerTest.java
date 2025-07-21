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
package dev.sigstore.encryption.signers;

import com.google.common.hash.Hashing;
import dev.sigstore.AlgorithmRegistry;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class SignerTest {

  private static final byte[] CONTENT = "abcdef".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CONTENT_DIGEST = Hashing.sha256().hashBytes(CONTENT).asBytes();

  static Stream<Arguments> signerProvider() throws NoSuchAlgorithmException {
    var rsaSigner2048 =
        Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_2048_SHA256);
    var rsaSigner3072 =
        Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_3072_SHA256);
    var rsaSigner4096 =
        Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_RSA_PKCS1V15_4096_SHA256);
    var ecdsaSigner = Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256);
    return Stream.of(
        Arguments.arguments(rsaSigner2048, Verifiers.newVerifier(rsaSigner2048.getPublicKey())),
        Arguments.arguments(rsaSigner3072, Verifiers.newVerifier(rsaSigner3072.getPublicKey())),
        Arguments.arguments(rsaSigner4096, Verifiers.newVerifier(rsaSigner4096.getPublicKey())),
        Arguments.arguments(ecdsaSigner, Verifiers.newVerifier(ecdsaSigner.getPublicKey())));
  }

  @ParameterizedTest
  @MethodSource("signerProvider")
  public void testSign(Signer signer, Verifier verifier) throws Exception {
    var sig = signer.sign(CONTENT);
    Assertions.assertTrue(verifier.verify(CONTENT, sig));
    Assertions.assertTrue(verifier.verifyDigest(CONTENT_DIGEST, sig));
  }

  @ParameterizedTest
  @MethodSource("signerProvider")
  public void testSignDigest(Signer signer, Verifier verifier) throws Exception {
    var sig = signer.signDigest(CONTENT_DIGEST);
    Assertions.assertTrue(verifier.verify(CONTENT, sig));
    Assertions.assertTrue(verifier.verifyDigest(CONTENT_DIGEST, sig));
  }
}
