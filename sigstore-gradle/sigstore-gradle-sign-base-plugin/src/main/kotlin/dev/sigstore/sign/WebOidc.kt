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
package dev.sigstore.sign

import dev.sigstore.oidc.client.WebOidcClient
import org.gradle.api.provider.Property
import org.gradle.util.GradleVersion
import java.io.Serializable
import javax.inject.Inject

abstract class WebOidc @Inject constructor() : OidcClientConfiguration, Serializable {
    abstract val clientId: Property<String>

    abstract val issuer: Property<String>

    init {
        try {
            clientId.convention("sigstore")
            issuer.convention(WebOidcClient.PUBLIC_DEX_ISSUER)
        } catch (e: NullPointerException) {
            // NPE here means Gradle tries to isolate WebOidc for passing it to WorkerAction parameters
            // Gradle 7.5.1 does not have such an issue, so rethrow unexpected NPEs
            if (GradleVersion.current() >= GradleVersion.version("7.5.1")) {
                throw e
            }
        }
    }

    override fun build(): Any =
        WebOidcClient.builder()
            .setClientId(clientId.get())
            .setIssuer(issuer.get())
            .build()
}
