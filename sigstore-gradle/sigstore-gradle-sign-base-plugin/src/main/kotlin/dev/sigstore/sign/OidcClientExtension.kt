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

import org.gradle.api.Action
import org.gradle.api.NamedDomainObjectProvider
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.provider.ProviderFactory
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.polymorphicDomainObjectContainer
import org.gradle.kotlin.dsl.register
import javax.inject.Inject

abstract class OidcClientExtension @Inject constructor(
    objects: ObjectFactory,
) {
    companion object {
        const val WEB_CLIENT_NAME = "web"
        const val GITHUB_ACTIONS_CLIENT_NAME = "gitHub"
    }

    val clients = objects.polymorphicDomainObjectContainer(OidcClientConfiguration::class)

    abstract val client: Property<OidcClientConfiguration>

    fun client(client: OidcClientConfiguration) {
        this.client.set(client)
    }

    init {
        clients.registerBinding(WebOidc::class.java, WebOidc::class.java)
        clients.registerBinding(GitHubActionsOidc::class.java, GitHubActionsOidc::class.java)
        clients.register<WebOidc>(WEB_CLIENT_NAME)
        val actionsOidcAvailable = System.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != null
        if (actionsOidcAvailable) {
            clients.register<GitHubActionsOidc>(GITHUB_ACTIONS_CLIENT_NAME)
        }
        // do not assign a default convention for client, that is delegated to KeylessSigner in
        // the default case.
    }

    private inline fun <reified T : OidcClientConfiguration> setup(
        name: String, configure: Action<T>? = null
    ) : NamedDomainObjectProvider<T> =
        if (clients.findByName(name) == null) {
            clients.register<T>(name)
        } else {
            clients.named<T>(name)
        }.apply {
            if (configure != null) {
                configure(configure)
            }
        }

    val web: NamedDomainObjectProvider<WebOidc>
        get() = setup(WEB_CLIENT_NAME)

    @JvmOverloads
    fun web(configure: Action<WebOidc>? = null) {
        setup(WEB_CLIENT_NAME, configure)
    }

    val gitHub: NamedDomainObjectProvider<GitHubActionsOidc>
        get() = setup(GITHUB_ACTIONS_CLIENT_NAME)

    @JvmOverloads
    fun gitHub(configure: Action<GitHubActionsOidc>? = null) {
        setup(GITHUB_ACTIONS_CLIENT_NAME, configure)
    }
}
