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

/**
 * Lists sigstore-java versions for backward compatibility testing of Sigstore Gradle plugin.
 */
sealed class TestedSigstoreJava {
    /**
     * sigstore-java version is unset, so sigstore-gradle should use the default version that is bundled with the plugin.
     */
    object Default: TestedSigstoreJava() {
        override fun toString() = "Default"
    }

    /**
     * Configures taken from external repository sigstore-java version for testing with Sigstore Gradle plugin.
     */
    data class Version(
        val version: String,
    ): TestedSigstoreJava()

    /**
     * Configures locally-built sigstore-java version for testing with Sigstore Gradle plugin.
     */
    data class LocallyBuiltVersion(
        val version: String,
    ): TestedSigstoreJava()
}
