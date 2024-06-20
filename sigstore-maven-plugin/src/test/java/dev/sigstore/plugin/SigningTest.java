/*
 * Copyright 2024 The Sigstore Authors.
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
 */
package dev.sigstore.plugin;

import dev.sigstore.plugin.test.MavenTestProject;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.it.VerificationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SigningTest {

  @TempDir public static Path testRoot;

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.ANY)
  public void test_simpleProject() throws IOException, VerificationException {
    var testProject = new MavenTestProject(testRoot, "simple");
    var verifier = testProject.newVerifier();

    verifier.executeGoal("package");
    verifier.verifyErrorFreeLog();
    verifier.verifyFilePresent("target/simple-it-1.0-SNAPSHOT.jar.sigstore.json");
    verifier.verifyFilePresent("target/simple-it-1.0-SNAPSHOT.pom.sigstore.json");
  }
}
