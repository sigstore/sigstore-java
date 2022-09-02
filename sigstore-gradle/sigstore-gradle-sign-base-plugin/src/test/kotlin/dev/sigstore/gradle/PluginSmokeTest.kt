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

import dev.sigstore.testkit.gradle.project
import dev.sigstore.sign.SigstoreSignExtension
import dev.sigstore.sign.tasks.SigstoreSignFilesTask
import dev.sigstore.testkit.BaseGradleTest
import org.assertj.core.api.Assertions
import org.gradle.api.tasks.WriteProperties
import org.gradle.kotlin.dsl.apply
import org.junit.jupiter.api.Test
import org.gradle.kotlin.dsl.*

class PluginSmokeTest : BaseGradleTest() {
    @Test
    fun `dev_sigstore_sign applies`() {
        project {
            apply(plugin = "dev.sigstore.sign-base")
        }
    }

    @Test
    fun `sign task dsl`() {
        project {
            apply(plugin = "dev.sigstore.sign-base")
            val hello by tasks.registering(WriteProperties::class) {
                outputFile = layout.buildDirectory.file("props/$name.properties").get().asFile
                property("hello", "world")
            }

            // It should be eagerly created to access signOutput
            val signFile by tasks.registering(SigstoreSignFilesTask::class) {
                signFile(hello.map { it.outputFile })
            }

            Assertions.assertThat(signFile.flatMap { it.singleSignature() }.get().asFile)
                .hasFileName("hello.properties.sigstore")
        }
    }

    @Test
    fun `oidcClient dsl`() {
        project {
            apply(plugin = "dev.sigstore.sign-base")
            configure<SigstoreSignExtension> {
                oidcClient {
                    // Note: the code is red in IDEA because it does not understand
                    // there's sam-with-receiver plugin for Action<.>
                    gitHub {
                        audience.set("sigstore-test")
                    }
                    web {
                        clientId.set("sigstore-test")
                    }
                }
            }
        }
    }
}
