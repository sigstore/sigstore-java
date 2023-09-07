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
package dev.sigstore.trustroot;

import dev.sigstore.encryption.Keys;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.immutables.value.Value.Immutable;
import org.immutables.value.Value.Lazy;

@Immutable
public abstract class PublicKey {
  public abstract byte[] getRawBytes();

  public abstract String getKeyDetails();

  public abstract ValidFor getValidFor();

  @Lazy
  public java.security.PublicKey toJavaPublicKey()
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    if (getKeyDetails().equals("PKIX_ECDSA_P256_SHA_256")) {
      return Keys.parsePkixPublicKey(getRawBytes(), "EC");
    }
    if (getKeyDetails().equals("PKCS1_RSA_PKCS1V5")) {
      return Keys.parsePkcs1RsaPublicKey(getRawBytes());
    }
    throw new InvalidKeySpecException("Unsupported key algorithm: " + getKeyDetails());
  }

  public static PublicKey from(dev.sigstore.proto.common.v1.PublicKey proto) {
    return ImmutablePublicKey.builder()
        .rawBytes(proto.getRawBytes().toByteArray())
        .keyDetails(proto.getKeyDetails().name())
        .validFor(ValidFor.from(proto.getValidFor()))
        .build();
  }
}
