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
import dev.sigstore.sign.SigstoreSignExtension
import dev.sigstore.sign.services.SigstoreSigningService

// https://github.com/gradle/gradle/pull/16627
inline fun <reified T: Named> AttributeContainer.attribute(attr: Attribute<T>, value: String) =
    attribute(attr, objects.named<T>(value))

val sigstoreSign = extensions.create("sigstoreSign", SigstoreSignExtension::class, project)

gradle.sharedServices.registerIfAbsent(SigstoreSigningService.SERVICE_NAME, SigstoreSigningService::class) {
    parameters {
        // Prevents concurrent execution of tasks that use the service, so we ensure there's only one signing task active at a time
        maxParallelUsages.set(1)
    }
}

val sigstoreClient by configurations.creating {
    description = "Declares sigstore client dependencies"
    isCanBeResolved = false
    isCanBeConsumed = false
    defaultDependencies {
        // Default dependency
        val version = sigstoreSign.sigstoreJavaVersion.get()
        add(project.dependencies.create("dev.sigstore:sigstore-java:$version"))
    }
}

val sigstoreClientClasspath by configurations.creating {
    description = "Resolves Sigstore dependencies"
    isCanBeResolved = true
    isCanBeConsumed = false
    extendsFrom(sigstoreClient)
    attributes {
        attribute(Category.CATEGORY_ATTRIBUTE, Category.LIBRARY)
        attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, LibraryElements.JAR)
        attribute(Usage.USAGE_ATTRIBUTE, Usage.JAVA_RUNTIME)
        attribute(Bundling.BUNDLING_ATTRIBUTE, Bundling.EXTERNAL)
        attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, JavaVersion.current().majorVersion.toInt())
    }
}
