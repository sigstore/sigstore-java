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
import dev.sigstore.testkit.annotations.EnabledIfOidcExists
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

@EnabledIfOidcExists
@Disabled("Disabled until 2.0 release")
class SigstoreSignTest: BaseGradleTest() {
    @ParameterizedTest
    @MethodSource("gradleVersionAndSettings")
    fun `sign file`(gradleVersion: String, configurationCache: ConfigurationCache) {
        writeBuildGradle(
            """
            import dev.sigstore.sign.tasks.SigstoreSignFilesTask
            plugins {
                id("java")
                id("dev.sigstore.sign-base")
            }
            repositories {
                mavenCentral()
            }
            group = "dev.sigstore.test"
            def helloProps = tasks.register("helloProps", WriteProperties) {
                outputFile = file("build/helloProps.txt")
                property("helloProps", "world")
            }
            def signFile = tasks.register("signFile", SigstoreSignFilesTask) {
                signFile(helloProps.map { it.outputFile })
                    .outputSignature.set(file("build/helloProps.txt.sigstore"))
            }
            """.trimIndent()
        )
        writeSettingsGradle(
            """
            rootProject.name = 'sigstore-test'
            """.trimIndent()
        )
        enableConfigurationCache(gradleVersion, configurationCache)
        prepare(gradleVersion, "signFile", "-s")
            .build()
        assertThat(projectDir.resolve("build/helloProps.txt.sigstore"))
            .content()
            .basicSigstoreStructure()

        if (configurationCache == ConfigurationCache.ON) {
            val result = prepare(gradleVersion, "signFile", "-s")
                .build()

            assertThat(result.output)
                .contains(
                    "Configuration cache entry reused",
                    "2 actionable tasks: 1 executed, 1 up-to-date",
                )
        }
    }
}
