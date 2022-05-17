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

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

/** A signing helper that wraps common signing operations for use within this library. */
public interface Signer {

  /** Return the public key associated with this signer. */
  PublicKey getPublicKey();

  /**
   * Sign the content. Implementations should use an algorithm that hashes with sha256 before
   * signing.
   *
   * @param content the full content to be signed (not a digest)
   * @param charset the charset of the string {@code content}
   */
  byte[] sign(String content, Charset charset)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

  /**
   * Sign the content. Implementations should use an algorithm that hashes with sha256 before
   * signing.
   *
   * @param content the full content to be signed (not a digest)
   */
  byte[] sign(byte[] content)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
