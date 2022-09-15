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
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.internal.DefaultGradleRunner
import org.gradle.util.GradleVersion
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.io.CleanupMode
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.Arguments.arguments
import java.nio.file.Path

open class BaseGradleTest {
    enum class ConfigurationCache {
        ON, OFF
    }

    protected val gradleRunner = GradleRunner.create().withPluginClasspath()

    companion object {
        val isCI = System.getenv().containsKey("CI") || System.getProperties().containsKey("CI")

        @JvmStatic
        fun gradleVersionAndSettings(): Iterable<Arguments> {
            if (!isCI) {
                // Make the test faster, and skip extra tests with the configuration cache to reduce OIDC flows
                // Gradle 7.2 fails with "No service of type ObjectFactory available in default services"
                return listOf(arguments("7.3", ConfigurationCache.OFF))
            }
            return mutableListOf<Arguments>().apply {
                add(arguments("7.3", ConfigurationCache.ON))
                add(arguments("7.5.1", ConfigurationCache.ON))
                add(arguments("7.5.1", ConfigurationCache.OFF))
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

    protected fun createSettings(extra: String = "") {
        projectDir.resolve("settings.gradle").write(
            """
                rootProject.name = 'sample'

                $extra
            """
        )
    }

    protected fun prepare(gradleVersion: String, vararg arguments: String) =
        gradleRunner
            .withGradleVersion(gradleVersion)
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
        gradleVersion: String,
        configurationCache: ConfigurationCache
    ) {
        if (configurationCache != ConfigurationCache.ON) {
            return
        }
        if (GradleVersion.version(gradleVersion) < GradleVersion.version("7.0")) {
            Assertions.fail<Unit>("Gradle version $gradleVersion does not support configuration cache")
        }
        // Gradle 6.5 expects values ON, OFF, WARN, so we add the option for 7.0 only
        projectDir.resolve("gradle.properties").toFile().appendText(
            """

            org.gradle.unsafe.configuration-cache=true
            org.gradle.unsafe.configuration-cache-problems=fail
            """.trimIndent()
        )
    }

    protected fun <SELF : AbstractCharSequenceAssert<SELF, ACTUAL>, ACTUAL : CharSequence> AbstractCharSequenceAssert<SELF, ACTUAL>.basicSigstoreStructure() =
        contains(
            """"mediaType" : "application/vnd.dev.sigstore.bundle.v1+json"""",
            """"algorithm" : "sha256"""",
        )
}
