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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class InclusionProofVerifierTest {
  public static byte[] leafHash;
  public static long logIndex;
  public static long treeSize;
  public static List<byte[]> proofHashes;
  public static byte[] expectedRootHash;

  @BeforeAll
  public static void initValues() throws Exception {
    leafHash = Hex.decode("ac3650aee1c1b3821211cf07067c1a118d0a7f86867bbb1df340cb8fc9c221af");
    logIndex = 1227L;
    treeSize = 14358L;
    proofHashes =
        List.of(
            Hex.decode("810320ec3029914695826d60133c67021f66ee0cfb09a6f79eb267ed9f55de2c"),
            Hex.decode("67e9d9f66f0ad388f7e1a20991e9a2ae3efad5cbf281e8b3d2aaf1ef99a4618c"),
            Hex.decode("16a106400c53465f6e18c2475df6ba889ca30f5667bacf32b1a5661f14a5080c"),
            Hex.decode("b4439e8d71edbc96271723cb7a969dd725e23e73d139361864a62ed76ce8dc11"),
            Hex.decode("49b3e90806c7b63b5a86f5748e3ecb7d264ea0828eb74a45bc1a2cd7962408e8"),
            Hex.decode("5059ad9b48fa50bd9adcbff0dd81c5a0dcb60f37e0716e723a33805a464f72f8"),
            Hex.decode("6c2ce64219799e61d72996884eee9e19fb906e4d7fa04b71625fde4108f21762"),
            Hex.decode("784f79c817abb78db3ae99b6c1ede640470bf4bb678673a05bf3a6b50aaaddd6"),
            Hex.decode("c6d92ebf4e10cdba500ca410166cd0a8d8b312154d2f45bc4292d63dea6112f6"),
            Hex.decode("1768732027401f6718b0df7769e2803127cfc099eb130a8ed7d913218f6a65f6"),
            Hex.decode("0da021f68571b65e49e926e4c69024de3ac248a1319d254bc51a85a657b93c33"),
            Hex.decode("bc8cf0c8497d5c24841de0c9bef598ec99bbd59d9538d58568340646fe289e9a"),
            Hex.decode("be328fa737b8fa9461850b8034250f237ff5b0b590b9468e6223968df294872b"),
            Hex.decode("6f06f4025d0346f04830352b23f65c8cd9e3ce4b8cb899877c35282521ddaf85"));
    expectedRootHash =
        Hex.decode("effa4fa4575f72829016a64e584441203de533212f9470d63a56d1992e73465d");
  }

  @Test
  public void verify() throws Exception {
    InclusionProofVerifier.verify(leafHash, logIndex, treeSize, proofHashes, expectedRootHash);
  }

  @Test
  public void verify_endPrematurely() throws Exception {
    var invalidTreeSize = 1;

    var thrown =
        assertThrows(
            InclusionProofVerificationException.class,
            () -> {
              InclusionProofVerifier.verify(
                  leafHash, logIndex, invalidTreeSize, proofHashes, expectedRootHash);
            });
    assertEquals("Inclusion proof failed, ended prematurely", thrown.getMessage());
  }

  @Test
  public void verify_rootHashMismatch() throws Exception {
    var unexpectedRootHash =
        Hex.decode("effa4fa4575f72829016a64e584441203de533212f9470d63a56d1992e73465e");

    var thrown =
        assertThrows(
            InclusionProofVerificationException.class,
            () -> {
              InclusionProofVerifier.verify(
                  leafHash, logIndex, treeSize, proofHashes, unexpectedRootHash);
            });
    assertTrue(
        thrown
            .getMessage()
            .startsWith("Calculated inclusion proof root hash does not match provided root hash"));
  }

  @Test
  public void hashChildren() {
    byte[] left = Hex.decode("7170380079683de93335f887309004415054475045b410300586503918910106");
    byte[] right = Hex.decode("a45db0765e04aa28507698b000d4859f9066055a02895bd8083004890de15892");
    byte[] expectedParentHash =
        Hex.decode("467bd65e6c49dbf8f89ddcbf1537aac7a61a7be1b87182393c66ce25050d03c2");
    assertArrayEquals(expectedParentHash, InclusionProofVerifier.hashChildren(left, right));
  }

  @Test
  public void combineBytes() {
    byte[] first = {0x01, 0x02};
    byte[] second = {0x03, 0x04};
    byte[] expected = {0x01, 0x02, 0x03, 0x04};
    assertArrayEquals(expected, InclusionProofVerifier.combineBytes(first, second));
  }

  @Test
  public void combineBytes_firstArrayEmpty() {
    byte[] first = {};
    byte[] second = {0x03, 0x04};
    assertArrayEquals(second, InclusionProofVerifier.combineBytes(first, second));
  }

  @Test
  public void combineBytes_secondArrayEmpty() {
    byte[] first = {0x01, 0x02};
    byte[] second = {};
    assertArrayEquals(first, InclusionProofVerifier.combineBytes(first, second));
  }
}
