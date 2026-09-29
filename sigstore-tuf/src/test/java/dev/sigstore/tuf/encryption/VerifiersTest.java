/*
 * Copyright 2024 The Sigstore Authors.
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
package dev.sigstore.tuf.encryption;

import com.google.common.io.Resources;
import dev.sigstore.tuf.model.ImmutableKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class VerifiersTest {

  static final String RSA_PUB_PATH = "dev/sigstore/samples/keys/test-rsa.pub";
  static final String EC_PUB_PATH = "dev/sigstore/samples/keys/test-ec.pub";

  @Test
  public void newVerifierRSA() throws Exception {
    var key =
        ImmutableKey.builder()
            .keyType("rsa")
            .keyVal(
                Map.of(
                    "public",
                    Resources.toString(
                        Resources.getResource(RSA_PUB_PATH), StandardCharsets.UTF_8)))
            .scheme("rsassa-pss-sha256")
            .build();
    var verifier = Verifiers.newVerifier(key);
    Assertions.assertTrue(verifier instanceof RsaPssVerifier);
  }

  @Test
  public void newVerifierRSA_unsupportedScheme() throws Exception {
    var key =
        ImmutableKey.builder()
            .keyType("rsa")
            .keyVal(
                Map.of(
                    "public",
                    Resources.toString(
                        Resources.getResource(RSA_PUB_PATH), StandardCharsets.UTF_8)))
            .scheme("rsa-junk")
            .build();
    Assertions.assertThrows(InvalidKeyException.class, () -> Verifiers.newVerifier(key));
  }

  @Test
  public void newVerifierECDSA() throws Exception {
    var key =
        ImmutableKey.builder()
            .keyType("ecdsa")
            .keyVal(
                Map.of(
                    "public",
                    Resources.toString(Resources.getResource(EC_PUB_PATH), StandardCharsets.UTF_8)))
            .scheme("ecdsa-sha2-nistp256")
            .build();
    var verifier = Verifiers.newVerifier(key);
    Assertions.assertTrue(verifier instanceof EcdsaVerifier);
  }

  @Test
  public void newVerifierECDSA_unsupportedScheme() throws Exception {
    var key =
        ImmutableKey.builder()
            .keyType("ecdsa")
            .keyVal(
                Map.of(
                    "public",
                    Resources.toString(
                        Resources.getResource(RSA_PUB_PATH), StandardCharsets.UTF_8)))
            .scheme("ecdsa-junk")
            .build();
    Assertions.assertThrows(InvalidKeyException.class, () -> Verifiers.newVerifier(key));
  }

  @Test
  public void newVerifierEd25519() throws Exception {
    var key =
        ImmutableKey.builder()
            .keyType("ed25519")
            .keyVal(
                Map.of(
                    "public", "2d7218ce609f85de4b0d29d9e679cfd73e96756652f7069a0cf00acb752e5d3c"))
            .scheme("ed25519")
            .build();
    var verifier = Verifiers.newVerifier(key);
    Assertions.assertTrue(verifier instanceof Ed25519Verifier);
  }

  @Test
  public void newVerifierEd25519_unsupportedScheme() {
    var key =
        ImmutableKey.builder()
            .keyType("ed25519")
            .keyVal(
                Map.of(
                    "public", "2d7218ce609f85de4b0d29d9e679cfd73e96756652f7069a0cf00acb752e5d3c"))
            .scheme("ed25519junk")
            .build();
    Assertions.assertThrows(InvalidKeyException.class, () -> Verifiers.newVerifier(key));
  }
}
