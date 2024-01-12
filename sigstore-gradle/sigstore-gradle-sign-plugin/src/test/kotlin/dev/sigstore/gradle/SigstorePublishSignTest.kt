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
import dev.sigstore.testkit.TestedGradleAndSigstoreJava
import dev.sigstore.testkit.TestedSigstoreJava
import dev.sigstore.testkit.annotations.EnabledIfOidcExists
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

@EnabledIfOidcExists
class SigstorePublishSignTest : BaseGradleTest() {
    @ParameterizedTest
    @MethodSource("gradleAndSigstoreJavaVersions")
    fun `sign file`(case: TestedGradleAndSigstoreJava) {
        writeBuildGradle(
            """
            plugins {
                id("java")
                id("maven-publish")
                id("dev.sigstore.sign")
            }
            ${declareRepositoryAndDependency(case.sigstoreJava)}

            group = "dev.sigstore.test"
            java {
                withSourcesJar()
            }
            publishing {
                publications {
                    maven(MavenPublication) {
                        groupId = 'dev.sigstore.test'
                        artifactId = 'sigstore-test'
                        version = '1.0'
                        from components.java
                    }
                }
                repositories {
                    maven {
                        name = "tmp"
                        url = layout.buildDirectory.dir("tmp-repo")
                    }
                }
            }
            """.trimIndent()
        )
        writeSettingsGradle(
            """
            rootProject.name = 'sigstore-test'
            """.trimIndent()
        )
        enableConfigurationCache(case.gradle)
        prepare(case.gradle.version, "publishAllPublicationsToTmpRepository", "-s")
            .build()

        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/sigstore-test-1.0.pom.sigstore"))
            .content()
            .basicSigstoreStructure()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/sigstore-test-1.0.jar.sigstore"))
            .content()
            .basicSigstoreStructure()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/sigstore-test-1.0-sources.jar.sigstore"))
            .content()
            .basicSigstoreStructure()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/sigstore-test-1.0.module.sigstore"))
            .content()
            .basicSigstoreStructure()

        if (case.gradle.configurationCache == ConfigurationCache.ON) {
            val result = prepare(case.gradle.version, "publishAllPublicationsToTmpRepository", "-s")
                .build()

            assertThat(result.output)
                .contains(
                    "Configuration cache entry reused",
                    "6 actionable tasks: 4 executed, 2 up-to-date",
                )
        }
    }
}
