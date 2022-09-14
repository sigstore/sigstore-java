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
package dev.sigstore.testkit.annotations

import dev.sigstore.testkit.EnableIfOidcExistsCondition
import org.junit.jupiter.api.condition.DisabledIfSystemProperty
import org.junit.jupiter.api.extension.ExtendWith

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@DisabledIfSystemProperty(
    named = "sigstore-java.test.skipOidc",
    matches = "^\\s*+(true|y|on|)\\s*+$",
    disabledReason = "sigstore-java.test.skipOidc system property is present",
)
@ExtendWith(EnableIfOidcExistsCondition::class)
annotation class EnabledIfOidcExists(
    val provider: OidcProviderType = OidcProviderType.ANY
)
