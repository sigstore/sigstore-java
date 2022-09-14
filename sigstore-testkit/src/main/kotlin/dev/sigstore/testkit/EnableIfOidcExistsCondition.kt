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

import dev.sigstore.testkit.annotations.EnabledIfOidcExists
import dev.sigstore.testkit.annotations.OidcProviderType
import org.junit.jupiter.api.extension.ConditionEvaluationResult
import org.junit.jupiter.api.extension.ConditionEvaluationResult.disabled
import org.junit.jupiter.api.extension.ConditionEvaluationResult.enabled
import org.junit.jupiter.api.extension.ExecutionCondition
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.platform.commons.util.AnnotationUtils

class EnableIfOidcExistsCondition : ExecutionCondition {
    override fun evaluateExecutionCondition(context: ExtensionContext): ConditionEvaluationResult {
        val element = context.element.orElse(null)
        val provider = AnnotationUtils.findAnnotation(element, EnabledIfOidcExists::class.java)
            .map { it.provider }.orElse(OidcProviderType.ANY)

        return when {
            provider == OidcProviderType.MANUAL ->
                if (System.getenv("CI") == "true") {
                    disabled("CI environment is present, and the test has been configured to run with MANUAL OIDC only")
                } else {
                    enabled("the test has been configured with MANUAL OIDC, and no CI environment variable is detected")
                }

            provider in listOf(OidcProviderType.ANY, OidcProviderType.CI, OidcProviderType.GITHUB) &&
                    System.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != null ->
                enabled("ACTIONS_ID_TOKEN_REQUEST_URL is present, so OIDC matches the requested $provider")

            else ->
                disabled("test requires $provider OIDC provider")
        }
    }
}
