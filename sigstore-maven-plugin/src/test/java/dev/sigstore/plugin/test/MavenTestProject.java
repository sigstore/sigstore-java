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
package dev.sigstore.plugin.test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;
import org.apache.maven.it.VerificationException;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;

/**
 * Initialize a test project verifier. You should use this to inject the right local repository into
 * settings.xml and the proejct version into pom.xml. Works with the test Maven projects in the
 * {@code resources/maven/projects} directory.
 */
public class MavenTestProject {

  private static final String PROJECTS_PATH_IN_RESOURCES = "/maven/projects/";
  private static final String SETTINGS_XML = "/maven/settings.xml";

  private final Path testDir;
  private final String testProjectName;

  public MavenTestProject(Path testDir, String testProjectName) {
    this.testDir = testDir;
    this.testProjectName = testProjectName;
  }

  public Verifier newVerifier() throws IOException, VerificationException {
    ResourceExtractor.extractResourcePath(
        MavenTestProject.class,
        PROJECTS_PATH_IN_RESOURCES + testProjectName,
        testDir.toFile(),
        true);

    File settingsXml =
        ResourceExtractor.extractResourceToDestination(
            MavenTestProject.class, SETTINGS_XML, testDir.resolve("settings.xml").toFile(), true);

    // properties are injected into the test task by the build (see
    // build-logic.depends-on-local-sigstore-java-repo.gradle.kts,
    // build-logic.depends-on-local-sigstore-maven-plugin-repo.gradle.kts)
    String pluginVersion = System.getProperty("sigstore.test.current.maven.plugin.version");

    try (var walker = Files.walk(testDir)) {
      var pomXmls =
          walker
              .filter(p -> p.getFileName().toString().equals("pom.xml"))
              .collect(Collectors.toList());
      for (var pomXml : pomXmls) {
        Files.write(
            pomXml,
            Files.readString(pomXml)
                .replace("@PluginVersion@", pluginVersion)
                .getBytes(StandardCharsets.UTF_8));
      }
    }

    var localMavenRepoProp = System.getProperty("sigstore.test.local.maven.repo");
    if (localMavenRepoProp == null) {
      throw new RuntimeException("no local repo configured for maven test");
    }
    var localMavenRepo = "file:///" + Paths.get(localMavenRepoProp).toRealPath();
    var localMavenRepoPluginProp = System.getProperty("sigstore.test.local.maven.plugin.repo");
    if (localMavenRepoPluginProp == null) {
      throw new RuntimeException("no local plugin repo configured for maven test");
    }
    var localMavenPluginRepo = "file:///" + Paths.get(localMavenRepoPluginProp).toRealPath();
    Files.write(
        settingsXml.toPath(),
        Files.readString(settingsXml.toPath())
            .replace("@localRepositoryUrl@", localMavenRepo)
            .replace("@localPluginRepositoryUrl@", localMavenPluginRepo)
            .getBytes(StandardCharsets.UTF_8));

    Path projectRoot = Paths.get(testDir.toString(), PROJECTS_PATH_IN_RESOURCES, testProjectName);
    var verifier = new Verifier(projectRoot.toAbsolutePath().toString());
    verifier.addCliOption("--settings=" + settingsXml.getCanonicalPath());
    return verifier;
  }
}
