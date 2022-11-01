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
package dev.sigstore.sign.work

import com.fasterxml.jackson.databind.ObjectMapper
import dev.sigstore.KeylessSigner
import dev.sigstore.oidc.client.OidcClient
import dev.sigstore.sign.OidcClientConfiguration
import dev.sigstore.sign.bundle.*
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.workers.WorkAction
import org.gradle.workers.WorkParameters
import org.slf4j.LoggerFactory
import java.util.*

abstract class SignWorkParameters : WorkParameters {
    abstract val inputFile: RegularFileProperty
    abstract val outputSignature: RegularFileProperty
    abstract val oidcClient: Property<OidcClientConfiguration>
}

private val jsonMapper = ObjectMapper().writerWithDefaultPrettyPrinter()

abstract class SignWorkAction : WorkAction<SignWorkParameters> {
    companion object {
        val logger = LoggerFactory.getLogger(SignWorkAction::class.java)
    }

    abstract val parameters: SignWorkParameters

    override fun execute() {
        val inputFile = parameters.inputFile.get().asFile
        logger.info("Signing in Sigstore: {}", inputFile)

        val signer = KeylessSigner.builder().apply {
            sigstorePublicDefaults()
            oidcClient(parameters.oidcClient.get().build() as OidcClient)
        }.build()

        val result = signer.signFile(inputFile.toPath())
        val signature = SigstoreBundle(
            mediaType = BundleMediaTypes.V1_JSON.value,
            timestampProof = RekorEntry(
                logIndex = result.entry.logIndex,
                logId = result.entry.logID,
                integratedTime = result.entry.integratedTime,
                signedEntryTimestamp = Base64.getDecoder().decode(result.entry.verification.signedEntryTimestamp),
            ),
            attestation = AttestationBlob(
                payloadHash = HashValue(
                    // See https://github.com/sigstore/sigstore-java/issues/85
                    algorithm = HashAlgorithm.sha256,
                    // https://github.com/sigstore/sigstore-java/issues/86
                    hash = result.digest.chunked(2)
                        .map { it.toInt(16).toByte() }
                        .toByteArray(),
                ),
                signature = result.signature,
            ),
            verificationMaterial = X509CertVerificationMaterial(
                chain = result.certPath.encoded,
            )
        )
        jsonMapper.writeValue(
            parameters.outputSignature.get().asFile,
            signature
        )
    }
}
