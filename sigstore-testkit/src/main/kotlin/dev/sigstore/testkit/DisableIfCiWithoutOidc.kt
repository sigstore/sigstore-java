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

import org.junit.jupiter.api.extension.ConditionEvaluationResult
import org.junit.jupiter.api.extension.ConditionEvaluationResult.disabled
import org.junit.jupiter.api.extension.ConditionEvaluationResult.enabled
import org.junit.jupiter.api.extension.ExecutionCondition
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@ExtendWith(DisableIfCiWithoutOidcCondition::class)
annotation class DisableIfCiWithoutOidc

class DisableIfCiWithoutOidcCondition : ExecutionCondition {
    override fun evaluateExecutionCondition(context: ExtensionContext): ConditionEvaluationResult {
        return when {
            System.getenv("CI") != "true" ->
                enabled("CI environment variable is not found")

            System.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == null ->
                disabled("ACTIONS_ID_TOKEN_REQUEST_URL environment variable is not found, so OIDC is not available")

            else ->
                enabled("CI=true and ACTIONS_ID_TOKEN_REQUEST_URL is present, so OIDC is available")
        }
    }
}
