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
import org.gradle.api.Task
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.publish.internal.PublicationInternal
import org.gradle.api.specs.Spec
import org.gradle.api.tasks.TaskProvider
import java.io.File

internal class DefaultDerivedArtifactFile(
    val task: TaskProvider<DefaultTask>,
    val fileProvider: Provider<RegularFile>,
) : PublicationInternal.DerivedArtifact {
    override fun create(): File =
        fileProvider.get().asFile

    override fun shouldBePublished(): Boolean =
        task.get().run { enabled && onlyIfSatisfied() }

    /**
     * Gradle 7.6 changed the type of `onlyIf` from `Spec<in Task>` to `SelfDescribingSpec<in Task>`,
     * so we need to use reflection to support slightly older Gradle versions in runtime.
     * @see [NoSuchMethodError org.gradle.api.DefaultTask.getOnlyIf when trying to run plugin compiled with Gradle 7.6 with Gradle 7.5.1](https://github.com/gradle/gradle/issues/23520)
     */
    private fun Task.onlyIfSatisfied() : Boolean {
        val getOnlyIf = DefaultTask::class.java.getMethod("getOnlyIf")
        @Suppress("UNCHECKED_CAST")
        val onlyIf = getOnlyIf.invoke(this) as Spec<in Task>
        return onlyIf.isSatisfiedBy(this)
    }
}
