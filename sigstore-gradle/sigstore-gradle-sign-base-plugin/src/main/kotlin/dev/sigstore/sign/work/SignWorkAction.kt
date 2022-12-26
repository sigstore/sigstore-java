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

import dev.sigstore.KeylessSigner
import dev.sigstore.bundle.BundleFactory
import dev.sigstore.oidc.client.OidcClient
import dev.sigstore.sign.OidcClientConfiguration
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.workers.WorkAction
import org.gradle.workers.WorkParameters
import org.slf4j.LoggerFactory

abstract class SignWorkParameters : WorkParameters {
    abstract val inputFile: RegularFileProperty
    abstract val outputSignature: RegularFileProperty
    abstract val oidcClient: Property<OidcClientConfiguration>
}

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
        val bundleJson = BundleFactory.createBundle(result)
        parameters.outputSignature.get().asFile.writeText(bundleJson)
    }
}
