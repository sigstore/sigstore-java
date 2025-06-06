/*
 * Copyright 2025 The Sigstore Authors.
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
package dev.sigstore.trustroot;

import static org.junit.jupiter.api.Assertions.*;

import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PublicKeyTest {

  @Test
  void toJavaPublicKey_edsa() throws Exception {
    var pk =
        makeKey(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==",
            "PKIX_ECDSA_P256_SHA_256");
    Assertions.assertEquals("ECDSA", pk.toJavaPublicKey().getAlgorithm());
  }

  @Test
  void toJavaPublicKey_edsaFail() {
    var pk = makeKey("eA==", "PKIX_ECDSA_P256_SHA_256");
    Assertions.assertThrows(InvalidKeySpecException.class, pk::toJavaPublicKey);
  }

  @Test
  void toJavaPublicKey_ed25519() throws Exception {
    var pk =
        makeKey("MCowBQYDK2VwAyEAPn+AREHoBaZ7wgS1zBqpxmLSGnyhxXj4lFxSdWVB8o8=", "PKIX_ED25519");
    Assertions.assertEquals("Ed25519", pk.toJavaPublicKey().getAlgorithm());
  }

  @Test
  void toJavaPublicKey_ed25519Fail() {
    var pk = makeKey("eA==", "PKIX_ED25519");
    Assertions.assertThrows(InvalidKeySpecException.class, pk::toJavaPublicKey);
  }

  @Test
  void toJavaPublicKey_rsa() throws Exception {
    var pk =
        makeKey(
            "MIICCgKCAgEA27A2MPQXm0I0v7/Ly5BIauDjRZF5Jor9vU+QheoE2UIIsZHcyYq3slHzSSHy2lLj1ZD2d91CtJ492ZXqnBmsr4TwZ9jQ05tW2mGIRI8u2DqN8LpuNYZGz/f9SZrjhQQmUttqWmtu3UoLfKz6NbNXUnoo+NhZFcFRLXJ8VporVhuiAmL7zqT53cXR3yQfFPCUDeGnRksnlhVIAJc3AHZZSHQJ8DEXMhh35TVv2nYhTI3rID7GwjXXw4ocz7RGDD37ky6p39Tl5NB71gT1eSqhZhGHEYHIPXraEBd5+3w9qIuLWlp5Ej/K6Mu4ELioXKCUimCbwy+Cs8UhHFlqcyg4AysOHJwIadXIa8LsY51jnVSGrGOEBZevopmQPNPtyfFY3dmXSS+6Z3RD2Gd6oDnNGJzpSyEk410Ag5uvNDfYzJLCWX9tU8lIxNwdFYmIwpd89HijyRyoGnoJ3entd63cvKfuuix5r+GHyKp1Xm1L5j5AWM6P+z0xigwkiXnt+adexAl1J9wdDxv/pUFEESRF4DG8DFGVtbdH6aR1A5/vD4krO4tC1QYUSeyL5Mvsw8WRqIFHcXtgybtxylljvNcGMV1KXQC8UFDmpGZVDSHx6v3e/BHMrZ7gjoCCfVMZ/cFcQi0W2AIHPYEMH/C95J2r4XbHMRdYXpovpOoT5Ca78gsCAwEAAQ==",
            "PKCS1_RSA_PKCS1V5");
    Assertions.assertEquals("RSA", pk.toJavaPublicKey().getAlgorithm());
  }

  @Test
  void toJavaPublicKey_rsaFail() {
    var pk = makeKey("eA==", "PKCS1_RSA_PKCS1V5");
    Assertions.assertThrows(InvalidKeySpecException.class, pk::toJavaPublicKey);
  }

  static PublicKey makeKey(String b64, String keyDetails) {
    return ImmutablePublicKey.builder()
        .rawBytes(Base64.decode(b64))
        .keyDetails(keyDetails)
        .validFor(ImmutableValidFor.builder().start(Instant.now()).build())
        .build();
  }
}
