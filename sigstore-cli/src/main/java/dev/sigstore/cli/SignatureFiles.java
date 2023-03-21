/*
 * Copyright 2023 The Sigstore Authors.
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
package dev.sigstore.cli;

import java.nio.file.Path;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Option;

public class SignatureFiles {

  @ArgGroup(multiplicity = "1", exclusive = false)
  SigAndCert sigAndCert;

  public static class SigAndCert {
    @Option(
        names = {"--signature"},
        description = "path to signature file",
        required = true)
    Path signatureFile;

    @Option(
        names = {"--certificate"},
        description = "path to certificate file",
        required = true)
    Path certificateFile;
  }

  @Option(
      names = {"--bundle"},
      description = "path to bundle file",
      required = true)
  Path bundleFile;
}
