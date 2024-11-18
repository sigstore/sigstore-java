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
package dev.sigstore.encryption;

import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeysTest {

  @Test
  void parseRsa() throws InvalidKeySpecException {
    var base64Key =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAghWkDAnX9F5QZZ9NxIWg9vcjULtD/kkbQwlcSm22e06FrgOdiFy1fKN/Ng32qEk1ZIKyi0HFzZxzPIcvg7eaFTRb7+AQiG6eMDmUzPGr67Jp0Di2ncH9+uOZmv4PVKovvQLq7qnEwbDk0HttxUscLQ2e36Lfv/2lpGW7apVmHVMoC5kwZ3KTiAk/DUtDhD4VQjU2rBy6OneO6pm6vdNzG4Jktjc0uUKFCRRUzydGEh05PgC9vSQu/EOiU+7aQPV1ZDUGpjg9tOM0SgaTOU3YSUfGiXZNHoiS2HwLyQPaxiHR2NPVH75bwnUFBHhdMxT1rhU+yLhXaweDQW6GQ0ti8wIDAQAB";
    Assertions.assertEquals("RSA", Keys.parseRsa(Base64.decode(base64Key)).getAlgorithm());
  }

  @Test
  void parseRsa_bad() {
    var base64Key =
        "MIIBIjANBgkqhkiG8w0BAQEFAAOCAQ8AMIIBCgKCAQEAghWkDAnX9F5QZZ9NxIWg9vcjULtD/kkbQwlcSm22e06FrgOdiFy1fKN/Ng32qEk1ZIKyi0HFzZxzPIcvg7eaFTRb7+AQiG6eMDmUzPGr67Jp0Di2ncH9+uOZmv4PVKovvQLq7qnEwbDk0HttxUscLQ2e36Lfv/2lpGW7apVmHVMoC5kwZ3KTiAk/DUtDhD4VQjU2rBy6OneO6pm6vdNzG4Jktjc0uUKFCRRUzydGEh05PgC9vSQu/EOiU+7aQPV1ZDUGpjg9tOM0SgaTOU3YSUfGiXZNHoiS2HwLyQPaxiHR2NPVH75bwnUFBHhdMxT1rhU+yLhXaweDQW6GQ0ti8wIDAQAB";
    Assertions.assertThrows(
        InvalidKeySpecException.class, () -> Keys.parseRsa(Base64.decode(base64Key)));
  }

  @Test
  void parseRsaPkcs1() throws InvalidKeySpecException {
    var base64Key =
        "MIICCgKCAgEA27A2MPQXm0I0v7/Ly5BIauDjRZF5Jor9vU+QheoE2UIIsZHcyYq3slHzSSHy2lLj1ZD2d91CtJ492ZXqnBmsr4TwZ9jQ05tW2mGIRI8u2DqN8LpuNYZGz/f9SZrjhQQmUttqWmtu3UoLfKz6NbNXUnoo+NhZFcFRLXJ8VporVhuiAmL7zqT53cXR3yQfFPCUDeGnRksnlhVIAJc3AHZZSHQJ8DEXMhh35TVv2nYhTI3rID7GwjXXw4ocz7RGDD37ky6p39Tl5NB71gT1eSqhZhGHEYHIPXraEBd5+3w9qIuLWlp5Ej/K6Mu4ELioXKCUimCbwy+Cs8UhHFlqcyg4AysOHJwIadXIa8LsY51jnVSGrGOEBZevopmQPNPtyfFY3dmXSS+6Z3RD2Gd6oDnNGJzpSyEk410Ag5uvNDfYzJLCWX9tU8lIxNwdFYmIwpd89HijyRyoGnoJ3entd63cvKfuuix5r+GHyKp1Xm1L5j5AWM6P+z0xigwkiXnt+adexAl1J9wdDxv/pUFEESRF4DG8DFGVtbdH6aR1A5/vD4krO4tC1QYUSeyL5Mvsw8WRqIFHcXtgybtxylljvNcGMV1KXQC8UFDmpGZVDSHx6v3e/BHMrZ7gjoCCfVMZ/cFcQi0W2AIHPYEMH/C95J2r4XbHMRdYXpovpOoT5Ca78gsCAwEAAQ==";
    Assertions.assertEquals("RSA", Keys.parseRsaPkcs1(Base64.decode(base64Key)).getAlgorithm());
  }

  @Test
  void parseRsaPkcs1_bad() throws InvalidKeySpecException {
    var base64Key =
        "MIIBIjANBgkqikiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAghWkDAnX9F5QZZ9NxIWg9vcjULtD/kkbQwlcSm22e06FrgOdiFy1fKN/Ng32qEk1ZIKyi0HFzZxzPIcvg7eaFTRb7+AQiG6eMDmUzPGr67Jp0Di2ncH9+uOZmv4PVKovvQLq7qnEwbDk0HttxUscLQ2e36Lfv/2lpGW7apVmHVMoC5kwZ3KTiAk/DUtDhD4VQjU2rBy6OneO6pm6vdNzG4Jktjc0uUKFCRRUzydGEh05PgC9vSQu/EOiU+7aQPV1ZDUGpjg9tOM0SgaTOU3YSUfGiXZNHoiS2HwLyQPaxiHR2NPVH75bwnUFBHhdMxT1rhU+yLhXaweDQW6GQ0ti8wIDAQAB";
    Assertions.assertThrows(
        InvalidKeySpecException.class, () -> Keys.parseRsaPkcs1(Base64.decode(base64Key)));
  }

  @Test
  void parseEd25519() throws InvalidKeySpecException {
    var base64Key = "MCowBQYDK2VwAyEAixzZOnx34hveTZ69J5iBCkmerK5Oh7EzJqTh3YY55jI=";
    Assertions.assertEquals("Ed25519", Keys.parseEd25519(Base64.decode(base64Key)).getAlgorithm());
  }

  @Test
  void parseEd25519_bad() {
    var base64Key = "MCowBQYDK2VxAyEAixzZOnx34hveTZ69J5iBCkmerK5Oh7EzJqTh3YY55jI=";
    Assertions.assertThrows(
        InvalidKeySpecException.class, () -> Keys.parseEd25519(Base64.decode(base64Key)));
  }

  @Test
  void parseEcdsa() throws InvalidKeySpecException {
    var base64Key =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVqBnvab9XEVlTLW4iGKBIdrL6Sxf0x5vclZyXtR6hl79/o+RSgyr1ZQKLLCUC20imDWUgFMmfLu4UUiKNcI2uQ==";
    Assertions.assertNotNull(Keys.parseEcdsa(Base64.decode(base64Key)));
  }

  @Test
  void parseEcdsa_bad() {
    var base64Key =
        "MFkwEwYHKoZIzj0CAQYIKoZJzj0DAQcDQgAEVqBnvab9XEVlTLW4iGKBIdrL6Sxf0x5vclZyXtR6hl79/o+RSgyr1ZQKLLCUC20imDWUgFMmfLu4UUiKNcI2uQ==";
    Assertions.assertThrows(
        InvalidKeySpecException.class, () -> Keys.parseEcdsa(Base64.decode(base64Key)));
  }
}
