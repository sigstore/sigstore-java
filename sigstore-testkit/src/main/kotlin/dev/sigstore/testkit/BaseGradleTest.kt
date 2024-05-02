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
package dev.sigstore.testkit

import org.assertj.core.api.AbstractCharSequenceAssert
import org.assertj.core.api.SoftAssertions
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.internal.DefaultGradleRunner
import org.gradle.util.GradleVersion
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.io.CleanupMode
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.Arguments.arguments
import java.io.File
import java.nio.file.Path

open class BaseGradleTest {
    enum class ConfigurationCache {
        ON, OFF
    }

    // to debug these tests, add .withDebug(true) before running a test in debug mode
    protected val gradleRunner = GradleRunner.create().withPluginClasspath()

    companion object {
        val isCI = System.getenv().containsKey("CI") || System.getProperties().containsKey("CI")

        val EXTRA_LOCAL_REPOS  = System.getProperty("sigstore.test.local.maven.repo").split(File.pathSeparatorChar)

        val SIGSTORE_JAVA_CURRENT_VERSION =
            TestedSigstoreJava.LocallyBuiltVersion(
                System.getProperty("sigstore.test.current.version")
            )

        @JvmStatic
        fun gradleVersions() = listOf(
            // Gradle 7.2 fails with "No service of type ObjectFactory available in default services"
            // So we require Gradle 7.3+
            "7.3",
            "7.5.1",
            "8.1",
            "8.5",
        ).map { GradleVersion.version(it) }

        @JvmStatic
        fun gradleVersionAndSettings(): Iterable<TestedGradle> {
            if (!isCI) {
                // Execute a single combination only when running locally
                return listOf(
                    TestedGradle(gradleVersions().first(), ConfigurationCache.ON)
                )
            }
            return buildList {
                addAll(
                    gradleVersions().map { TestedGradle(it, ConfigurationCache.ON) }
                )
                // Test the first and the last version without configuration cache
                add(TestedGradle(gradleVersions().first(), ConfigurationCache.OFF))
                add(TestedGradle(gradleVersions().last(), ConfigurationCache.OFF))
            }
        }

        @JvmStatic
        fun sigstoreJavaVersions(): Iterable<TestedSigstoreJava> {
            return buildList {
                add(SIGSTORE_JAVA_CURRENT_VERSION)
                // For now, we test the plugins only with locally-built sigstore-java version
                if (isCI && false) {
                    add(TestedSigstoreJava.Default)
                    // 0.3.0 is the minimal version that supports generating Sigstore Bundle
                    add(TestedSigstoreJava.Version("0.3.0"))
                }
            }
        }

        @JvmStatic
        fun gradleAndSigstoreJavaVersions(): Iterable<TestedGradleAndSigstoreJava> {
            val gradle = gradleVersionAndSettings()
            val sigstore = sigstoreJavaVersions()
            return gradle.flatMap { gradleVersion ->
                sigstore.map { TestedGradleAndSigstoreJava(gradleVersion, it) }
            }
        }
    }

    @TempDir(cleanup = CleanupMode.ON_SUCCESS)
    protected lateinit var projectDir: Path

    fun Path.write(text: String) = this.toFile().writeText(text)
    fun Path.read(): String = this.toFile().readText()

    fun writeBuildGradle(@Language("Groovy") text: String) = projectDir.resolve("build.gradle").write(text)
    fun writeSettingsGradle(@Language("Groovy") text: String) = projectDir.resolve("settings.gradle").write(text)

    protected fun String.normalizeEol() = replace(Regex("[\r\n]+"), "\n")

    protected fun declareRepositories(sigstoreJava: TestedSigstoreJava) =
        """
        repositories {${
            if (sigstoreJava is TestedSigstoreJava.Version) {
                ""
            } else {
                // We assume that the plugin defaults to the same version of the library, so we test both
                // Default and LocallyBuiltVersion from locally staged repo
                EXTRA_LOCAL_REPOS.joinToString("\n") {
                    """

                maven {
                   url = uri("${
                        File(it).toURI().toASCIIString().replace(Regex("""[\\"$]""")) { "\\" + it.value }
                   }")
                }
                """.trimIndent().prependIndent("            ")
                }
            }
        }
            mavenCentral()
        }
        """.trimIndent()

    protected fun declareDependency(sigstoreJava: TestedSigstoreJava) =
        """
        dependencies {
            ${
                when (sigstoreJava) {
                    TestedSigstoreJava.Default -> ""
                    is TestedSigstoreJava.Version ->
                        "sigstoreClient(\"dev.sigstore:sigstore-java:${sigstoreJava.version}\")"
                    is TestedSigstoreJava.LocallyBuiltVersion ->
                        "sigstoreClient(\"dev.sigstore:sigstore-java:${sigstoreJava.version}\")"
                }
            }
        }
        """.trimIndent()

    protected fun declareRepositoryAndDependency(sigstoreJava: TestedSigstoreJava) =
        """
        ${declareRepositories(sigstoreJava)}
        ${declareDependency(sigstoreJava)}
        """.trimIndent()


    protected fun createSettings(extra: String = "") {
        projectDir.resolve("settings.gradle").write(
            """
                rootProject.name = 'sample'

                $extra
            """
        )
    }

    protected fun prepare(gradleVersion: GradleVersion, vararg arguments: String) =
        gradleRunner
            .withGradleVersion(gradleVersion.version)
            .withProjectDir(projectDir.toFile())
            .apply {
                this as DefaultGradleRunner
                // See https://github.com/gradle/gradle/issues/10527
                // Gradle does not provide API to configure heap size for testkit-based Gradle executions,
                // so we resort to org.gradle.testkit.runner.internal.DefaultGradleRunner
                System.getProperty("sigstore-java.test.org.gradle.jvmargs")?.let { jvmArgs ->
                    withJvmArguments(
                        jvmArgs.split(Regex("\\s+"))
                            .map { it.trim() }
                            .filter { it.isNotBlank() }
                    )
                }
            }
            .withArguments(*arguments)
            .forwardOutput()

    protected fun enableConfigurationCache(
        gradle: TestedGradle,
    ) {
        if (gradle.configurationCache != ConfigurationCache.ON) {
            return
        }
        // Gradle 6.5 expects values ON, OFF, WARN, so we add the option for 7.0 only
        projectDir.resolve("gradle.properties").toFile().appendText(
            """

            org.gradle.unsafe.configuration-cache=true
            org.gradle.unsafe.configuration-cache-problems=fail
            """.trimIndent()
        )
    }

    protected fun assertSoftly(body: SoftAssertions.() -> Unit) =
        SoftAssertions.assertSoftly(body)

    protected fun <SELF : AbstractCharSequenceAssert<SELF, ACTUAL>, ACTUAL : CharSequence> AbstractCharSequenceAssert<SELF, ACTUAL>.basicSigstoreStructure() =
        contains(
            """"mediaType": "application/vnd.dev.sigstore.bundle+json;version\u003d0.3"""",
            """"algorithm": "SHA2_256"""",
        )
}
