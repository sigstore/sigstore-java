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

import dev.sigstore.testkit.BaseGradleTest
import dev.sigstore.testkit.TestedGradle
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class OidcDslTest: BaseGradleTest() {
    @ParameterizedTest
    @MethodSource("gradleVersionAndSettings")
    fun `configure GitHub OIDC client explicitly`(gradle: TestedGradle) {
        writeBuildGradle(
            """
            plugins {
                id("java")
                id("dev.sigstore.sign-base")
            }
            group = "dev.sigstore.test"
            sigstoreSign {
                oidcClient {
                    gitHub()
                }
            }
            tasks.create('printConfig') {
                def oidcClient = project.sigstoreSign.oidcClient.client
                doLast {
                    println("s: ${'$'}{oidcClient.get()}")
                }
            }
            """.trimIndent()
        )
        enableConfigurationCache(gradle)
        prepare(gradle.version, "printConfig", "-s")
            .build()
    }
}
