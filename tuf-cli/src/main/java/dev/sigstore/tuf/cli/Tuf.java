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
package dev.sigstore.tuf.cli;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

@Command(
    name = "tuf",
    mixinStandardHelpOptions = true,
    subcommands = {Init.class, Refresh.class, Download.class})
public class Tuf {
  @Spec CommandSpec spec;

  public CommandSpec getSpec() {
    return spec;
  }

  @Option(
      names = {"--metadata-dir"},
      required = false,
      paramLabel = "<METADATA_DIR>")
  private Path metadataDir;

  @Option(
      names = {"--metadata-url"},
      required = false,
      paramLabel = "<METADATA_URL>")
  private URI metadataUrl;

  @Option(
      names = {"--target-name"},
      required = false,
      paramLabel = "<TARGET_PATH>")
  private String targetName;

  @Option(
      names = {"--target-base-url"},
      required = false,
      paramLabel = "<TARGET_URL>")
  private URI targetBaseUrl;

  @Option(
      names = {"--target-dir"},
      required = false,
      paramLabel = "<TARGET_DIR>")
  private Path targetDir;

  private Clock clock = Clock.systemUTC();

  @Option(
      names = {"--time"},
      required = false)
  public void setTime(String epochSecond) {
    this.clock = Clock.fixed(Instant.ofEpochSecond(Long.parseLong(epochSecond)), ZoneOffset.UTC);
  }

  Path getMetadataDir() {
    if (metadataDir == null) {
      throw new ParameterException(spec.commandLine(), "--metadata-dir not set");
    }
    return metadataDir;
  }

  URI getMetadataUrl() {
    if (metadataUrl == null) {
      throw new ParameterException(spec.commandLine(), "--metadata-url not set");
    }
    return metadataUrl;
  }

  String getTargetName() {
    if (targetName == null) {
      throw new ParameterException(spec.commandLine(), "--target-name not set");
    }
    return targetName;
  }

  URI getTargetBaseUrl() {
    if (targetBaseUrl == null) {
      throw new ParameterException(spec.commandLine(), "--target-base-url not set");
    }
    return targetBaseUrl;
  }

  Path getTargetDir() {
    if (targetDir == null) {
      throw new ParameterException(spec.commandLine(), "--target-dir not set");
    }
    return targetDir;
  }

  public Clock getClock() {
    return clock;
  }

  public static void main(String[] args) {
    int exitCode = new CommandLine(new Tuf()).execute(args);
    System.exit(exitCode);
  }
}
