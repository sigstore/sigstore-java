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
import dev.sigstore.testkit.annotations.EnabledIfOidcExists
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.SoftAssertions
import org.gradle.util.GradleVersion
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

@EnabledIfOidcExists
class RemoveSigstoreAscTest : BaseGradleTest() {
    companion object {
        @JvmStatic
        fun signingSupportedGradleAndSigstoreJavaVersions(): Iterable<TestedGradleAndSigstoreJava> =
            gradleAndSigstoreJavaVersions()
                .filter {
                    it.gradle.configurationCache == ConfigurationCache.OFF ||
                            // Signing plugin supports configuration cache since 8.1
                            it.gradle.version >= GradleVersion.version("8.1")
                }.ifEmpty {
                    // When executing tests locally, the above gradleAndSigstoreJavaVersions might produce
                    // Gradle < 8.1 + configuration cache=on which is incompatible with signing plugin.
                    listOf(
                        TestedGradleAndSigstoreJava(
                            TestedGradle(GradleVersion.version("8.1"), ConfigurationCache.OFF),
                            SIGSTORE_JAVA_CURRENT_VERSION
                        )
                    )
                }

        @JvmStatic
        fun oneSigningSupportedGradleAndSigstoreJavaVersions(): Iterable<TestedGradleAndSigstoreJava> =
            signingSupportedGradleAndSigstoreJavaVersions().take(1)
    }

    @ParameterizedTest
    @MethodSource("signingSupportedGradleAndSigstoreJavaVersions")
    fun `basic configuration avoids signing sigstore with pgp`(case: TestedGradleAndSigstoreJava) {
        prepareBuildScripts(case)

        prepare(case.gradle.version, "publishAllPublicationsToTmpRepository", "-s")
            .build()

        assertSoftly {
            assertSignatures("sigstore-test-1.0.pom")
            assertSignatures("sigstore-test-1.0-sources.jar")
            assertSignatures("sigstore-test-1.0.module")
            assertSignatures("sigstore-test-1.0.pom")
        }

        if (case.gradle.configurationCache == ConfigurationCache.ON) {
            val result = prepare(case.gradle.version, "publishAllPublicationsToTmpRepository", "-s")
                .build()

            assertThat(result.output)
                .contains(
                    "Configuration cache entry reused",
                    "7 actionable tasks: 4 executed, 3 up-to-date",
                )
        }
    }

    @ParameterizedTest
    @MethodSource("oneSigningSupportedGradleAndSigstoreJavaVersions")
    fun `crossign sigstore with pgp`(case: TestedGradleAndSigstoreJava) {
        prepareBuildScripts(case)
        projectDir.resolve("gradle.properties").toFile().appendText(
            """

            # By default, dev.sigstore.sign asks Gradle to avoid signing .sigstore.json as
            # .sigstore.json.asc This is an opt-out hatch for those who need .sigstore.json.asc
            dev.sigstore.sign.remove.sigstore.asc=false
            """.trimIndent()
        )
        prepare(case.gradle.version, "publishAllPublicationsToTmpRepository", "-s")
            .build()
        assertSoftly {
            assertSignatures("sigstore-test-1.0.pom", expectSigstoreAsc = true)
            assertSignatures("sigstore-test-1.0-sources.jar", expectSigstoreAsc = true)
            assertSignatures("sigstore-test-1.0.module", expectSigstoreAsc = true)
            assertSignatures("sigstore-test-1.0.pom", expectSigstoreAsc = true)
        }
    }

    private fun prepareBuildScripts(case: TestedGradleAndSigstoreJava) {
        writeBuildGradle(
            """
            plugins {
                id("java")
                id("signing")
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
            signing {
                useInMemoryPgpKeys(
                  '''$testOnlySigningKey''',
                  "testforsigstorejava"
                )
                sign(publishing.publications.withType(MavenPublication))
            }
            """.trimIndent()
        )
        writeSettingsGradle(
            """
            rootProject.name = 'sigstore-test'
            """.trimIndent()
        )
        enableConfigurationCache(case.gradle)
    }

    private fun SoftAssertions.assertSignatures(name: String, expectSigstoreAsc: Boolean = false) {
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/$name.sigstore.json"))
            .describedAs("$name should be signed with Sigstore")
            .content()
            .basicSigstoreStructure()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/$name.asc"))
            .describedAs("$name should be signed with PGP")
            .isNotEmptyFile()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/$name.asc.sigstore"))
            .describedAs("$name.asc should NOT be signed with Sigstore")
            .doesNotExist()
        assertThat(projectDir.resolve("build/tmp-repo/dev/sigstore/test/sigstore-test/1.0/$name.sigstore.json.asc"))
            .apply {
                if (expectSigstoreAsc) {
                    describedAs("$name.sigstore.json should be signed with PGP")
                    exists()
                } else {
                    // We don't want to sign .sigstore.json files with PGP
                    describedAs("$name.sigstore.json should NOT be signed with PGP")
                    doesNotExist()
                }
            }
    }

    private val testOnlySigningKey = """
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        lIYEZaDRyxYJKwYBBAHaRw8BAQdAjMi3g07livoPo+se6/+wF7LRv2DDJ6UKVBrp
        9rugpwj+BwMCDZlNm7zWHTP6ny1jqI5sdTFaEkHRjFhm63Il9qeF7QcSibgAnBO5
        YK0E4vp8MUQxSAwoOV80mO46a2Ci9hA281lXH6fFTP3qyERXl2/ilrQvVGVzdCBL
        ZXkgZm9yIFNpZ3N0b3JlIEphdmEgPHNpZ3N0b3JlQGdpdGh1Yi5pbz6IkwQTFgoA
        OxYhBNejX8GGaAn2Jspav54UgcovliH1BQJloNHLAhsDBQsJCAcCAiICBhUKCQgL
        AgQWAgMBAh4HAheAAAoJEJ4UgcovliH1YDUBAPE1yBo7i4YgHuHKIGLqkOJqEKE5
        Jbw8ffyZO6tqud2qAP49liajq/HkdEXgUdA6DySpzLYFtd+F6UlpTQE0TeaLAA==
        =6fgq
        -----END PGP PRIVATE KEY BLOCK-----
    """.trimIndent()
}
