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
 *
 */
package dev.sigstore.gradle

import com.fasterxml.jackson.databind.ObjectMapper
import dev.sigstore.sign.bundle.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SigstoreBundleTest {
    @Test
    fun `sigstore bundle serialization test`() {
        val ss = SigstoreBundle(
            mediaType = BundleMediaTypes.V1_JSON.value,
            timestampProof = RekorEntry(
                logIndex = 2650032,
                logId = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                integratedTime = 1655148846,
                signedEntryTimestamp = byteArrayOf(3),
            ),
            attestation = AttestationBlob(
                payloadHash = HashValue(
                    algorithm = HashAlgorithm.sha256,
                    hash = byteArrayOf(1, 2, 3),
                ),
                signature = byteArrayOf(4, 5, 6)
            ),
            verificationMaterial = X509CertVerificationMaterial(
                chain = byteArrayOf(3, 4, 5)
            )
        )
        val json = ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(ss)
        assertThat(json)
            .isEqualToIgnoringNewLines(/* language=json */
                """
                {
                  "mediaType" : "application/vnd.dev.sigstore.bundle.v1+json",
                  "timestampProof" : {
                    "logIndex" : "2650032",
                    "logId" : "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                    "signedEntryTimestamp" : "Aw==",
                    "integratedTime" : "1655148846"
                  },
                  "verificationMaterial" : {
                    "chain" : "AwQF"
                  },
                  "attestation" : {
                    "payloadHash" : {
                      "algorithm" : "sha256",
                      "hash" : "010203"
                    },
                    "signature" : "BAUG"
                  }
                }
                """.trimIndent()
            )
    }
}
