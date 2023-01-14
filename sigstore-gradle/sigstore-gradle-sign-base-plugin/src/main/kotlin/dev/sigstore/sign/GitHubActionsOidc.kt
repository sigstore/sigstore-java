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

import dev.sigstore.oidc.client.GithubActionsOidcClient
import org.gradle.api.provider.Property
import org.gradle.util.GradleVersion
import javax.inject.Inject

abstract class GitHubActionsOidc @Inject constructor() : OidcClientConfiguration {
    abstract val audience: Property<String>

    init {
        try {
            audience.convention("sigstore")
        } catch (e: NullPointerException) {
            // NPE here means Gradle tries to isolate WebOidc for passing it to WorkerAction parameters
            // Gradle 7.5.1 does not have such an issue, so rethrow unexpected NPEs
            if (GradleVersion.current() >= GradleVersion.version("7.5.1")) {
                throw e
            }
        }
    }

    override fun build(): Any =
        GithubActionsOidcClient.builder()
            .audience(audience.get())
            .build()

    override fun key(): Any = audience.get()
}
