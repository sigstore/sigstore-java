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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.sigstore.plugin.test.MavenTestProject;
import dev.sigstore.testkit.annotations.EnabledIfOidcExists;
import dev.sigstore.testkit.annotations.OidcProviderType;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SigningTest {

  @TempDir public static Path testRoot;

  @Test
  @EnabledIfOidcExists(provider = OidcProviderType.ANY)
  public void test_simpleProject() throws IOException {
    var testProject = new MavenTestProject(testRoot, "simple");
    var result = testProject.execute("package");

    String stdOut = result.stdOutString().orElse("");
    String stdErr = result.stdErrString().orElse("");
    String logs = "stdout:\n" + stdOut + "\nstderr:\n" + stdErr;
    assertTrue(result.success(), "Maven execution failed:\n" + logs);
    assertFalse(stdOut.contains("[ERROR]"), "Maven stdout contained [ERROR]:\n" + logs);
    assertFalse(stdErr.contains("[ERROR]"), "Maven stderr contained [ERROR]:\n" + logs);
    assertThat(
            testProject.getProjectRoot().resolve("target/simple-it-1.0-SNAPSHOT.jar.sigstore.json"))
        .exists();
    assertThat(
            testProject.getProjectRoot().resolve("target/simple-it-1.0-SNAPSHOT.pom.sigstore.json"))
        .exists();
  }
}
