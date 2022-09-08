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
package dev.sigstore.sign

import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.publish.internal.PublicationInternal
import org.gradle.api.tasks.TaskProvider
import java.io.File

internal class DefaultDerivedArtifactFile(
    val task: TaskProvider<DefaultTask>,
    val fileProvider: Provider<RegularFile>,
) : PublicationInternal.DerivedArtifact {
    override fun create(): File =
        fileProvider.get().asFile

    override fun shouldBePublished(): Boolean =
        task.get().run { enabled && onlyIf.isSatisfiedBy(this) }
}
