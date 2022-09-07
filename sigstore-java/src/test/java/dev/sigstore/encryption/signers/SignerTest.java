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
    var rsaSigner = Signers.newRsaSigner();
    var ecdsaSigner = Signers.newEcdsaSigner();
    return Stream.of(
        Arguments.arguments(rsaSigner, Verifiers.newVerifier(rsaSigner.getPublicKey())),
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
