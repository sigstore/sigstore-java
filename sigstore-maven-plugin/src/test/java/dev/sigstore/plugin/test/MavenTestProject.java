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

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.apache.maven.executor.ExecutorRequest;
import org.apache.maven.executor.ExecutorResult;
import org.apache.maven.executor.forked.ForkedMavenExecutor;

/**
 * Initialize a test project executor. You should use this to inject the right local repository into
 * settings.xml and the project version into pom.xml. Works with the test Maven projects in the
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

  public Path getProjectRoot() {
    return Paths.get(testDir.toString(), PROJECTS_PATH_IN_RESOURCES, testProjectName);
  }

  public ExecutorResult execute(String... arguments) throws IOException {
    Path sourceDir;
    try {
      sourceDir =
          Paths.get(
              MavenTestProject.class
                  .getResource(PROJECTS_PATH_IN_RESOURCES + testProjectName)
                  .toURI());
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
    Path projectRoot = getProjectRoot();
    try (var stream = Files.walk(sourceDir)) {
      for (Path source : (Iterable<Path>) stream::iterator) {
        Path dest = projectRoot.resolve(sourceDir.relativize(source));
        if (Files.isDirectory(source)) {
          Files.createDirectories(dest);
        } else {
          Files.copy(source, dest);
        }
      }
    }

    Path settingsXml = testDir.resolve("settings.xml");
    try (var in = MavenTestProject.class.getResourceAsStream(SETTINGS_XML)) {
      Files.copy(in, settingsXml);
    }

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
        Files.writeString(
            pomXml,
            Files.readString(pomXml, StandardCharsets.UTF_8)
                .replace("@PluginVersion@", pluginVersion),
            StandardCharsets.UTF_8);
      }
    }

    var localMavenRepoProp = System.getProperty("sigstore.test.local.maven.repo");
    if (localMavenRepoProp == null) {
      throw new RuntimeException("no local repo configured for maven test");
    }
    var reposBuilder = new StringBuilder();
    var pluginReposBuilder = new StringBuilder();
    int idx = 0;
    for (String pathStr :
        localMavenRepoProp.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
      var repoUrl = "file:///" + Paths.get(pathStr).toRealPath();
      reposBuilder.append(
          String.format(
              java.util.Locale.ROOT,
              """
                  <repository>
                    <id>local.central.%d</id>
                    <url>%s</url>
                    <releases>
                      <enabled>true</enabled>
                    </releases>
                    <snapshots>
                      <enabled>true</enabled>
                    </snapshots>
                  </repository>
          """,
              idx,
              repoUrl));
      pluginReposBuilder.append(
          String.format(
              java.util.Locale.ROOT,
              """
                  <pluginRepository>
                    <id>local.central.%d</id>
                    <url>%s</url>
                    <releases>
                      <enabled>true</enabled>
                    </releases>
                    <snapshots>
                      <enabled>true</enabled>
                    </snapshots>
                  </pluginRepository>
          """,
              idx,
              repoUrl));
      idx++;
    }
    var localMavenRepoPluginProp = System.getProperty("sigstore.test.local.maven.plugin.repo");
    if (localMavenRepoPluginProp == null) {
      throw new RuntimeException("no local plugin repo configured for maven test");
    }
    var localMavenPluginRepo = "file:///" + Paths.get(localMavenRepoPluginProp).toRealPath();
    Files.writeString(
        settingsXml,
        Files.readString(settingsXml, StandardCharsets.UTF_8)
            .replace("@localRepositories@", reposBuilder.toString())
            .replace("@localPluginRepositories@", pluginReposBuilder.toString())
            .replace("@localPluginRepositoryUrl@", localMavenPluginRepo),
        StandardCharsets.UTF_8);

    try (var executor = new ForkedMavenExecutor(ExecutorRequest.discoverInstallationDirectory())) {
      var requestBuilder =
          ExecutorRequest.mavenBuilder()
              .cwd(getProjectRoot())
              .environmentVariable(
                  "JAVA_HOME",
                  System.getProperty(
                      "sigstore-java.test.JAVA_HOME", System.getProperty("java.home")))
              .argument("-e")
              .argument("--batch-mode")
              .argument("--settings=" + settingsXml.toRealPath())
              .grabOutputAsString(true);
      Arrays.stream(arguments).forEach(requestBuilder::argument);
      return executor.execute(requestBuilder.build());
    }
  }
}
