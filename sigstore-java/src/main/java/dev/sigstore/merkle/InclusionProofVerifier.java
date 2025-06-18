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
package dev.sigstore.merkle;

import com.google.common.hash.Hashing;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;

/** Verifier for inclusion proofs. */
public class InclusionProofVerifier {
  /**
   * Verifies an inclusion proof.
   *
   * @param leafHash the hash of the leaf entry.
   * @param logIndex the index of the leaf in the log.
   * @param treeSize the size of the tree at the time the proof was generated.
   * @param proofHashes a list of hashes from the inclusion proof.
   * @param expectedRootHash the expected root hash of the Merkle tree.
   * @throws InclusionProofVerificationException if the proof is invalid.
   */
  public static void verify(
      byte[] leafHash,
      long logIndex,
      long treeSize,
      List<byte[]> proofHashes,
      byte[] expectedRootHash)
      throws InclusionProofVerificationException {
    byte[] currentHash = leafHash;
    long nodeIndex = logIndex;
    long totalNodes = treeSize - 1;

    for (byte[] hash : proofHashes) {
      if (totalNodes == 0) {
        throw new InclusionProofVerificationException("Inclusion proof failed, ended prematurely");
      }
      if (nodeIndex == totalNodes || nodeIndex % 2 == 1) {
        currentHash = hashChildren(hash, currentHash);
        while (nodeIndex % 2 == 0) {
          nodeIndex = nodeIndex >> 1;
          totalNodes = totalNodes >> 1;
        }
      } else {
        currentHash = hashChildren(currentHash, hash);
      }
      nodeIndex = nodeIndex >> 1;
      totalNodes = totalNodes >> 1;
    }

    if (!Arrays.equals(currentHash, expectedRootHash)) {
      throw new InclusionProofVerificationException(
          "Calculated inclusion proof root hash does not match provided root hash\n"
              + "calculated: "
              + Hex.toHexString(currentHash)
              + "\n"
              + "provided:   "
              + Hex.toHexString(expectedRootHash));
    }
  }

  /**
   * Hashes the concatenation of a 0x01 byte, the left child hash, and the right child hash using
   * SHA-256.
   *
   * @param left the left child hash.
   * @param right the right child hash.
   * @return the parent hash.
   */
  public static byte[] hashChildren(byte[] left, byte[] right) {
    return Hashing.sha256()
        .newHasher()
        .putByte((byte) 0x01)
        .putBytes(left)
        .putBytes(right)
        .hash()
        .asBytes();
  }
}
