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
 */
package dev.sigstore.tuf.model;

import java.util.List;
import org.immutables.gson.Gson;
import org.immutables.value.Value;

/**
 * A metadata file provided by a Delegated Targets role will follow exactly the same format as one
 * provided by the top-level Targets role. A delegated role can specify additional targets scoped to
 * a specific namespace for that delegated role.
 *
 * @see <a href="https://theupdateframework.io/metadata/#delegated-targets-metadata-role1json">TUF
 *     delegated targets role documentation</a>
 */
@Gson.TypeAdapters
@Value.Immutable
public interface DelegationRole extends Role {

  /**
   * A string giving the name of the delegated role. For example, "projects". The rolename MUST be
   * unique in the delegations object: multiple roles with the same rolename are not allowed within
   * a DELEGATIONS.
   */
  String getName();

  /**
   * A list of strings, where each string is a PATHPATTERN describing a path that the delegated role
   * is trusted to provide. Clients MUST check that a target is in one of the trusted paths of all
   * roles in a delegation chain, not just in a trusted path of the role that describes the target
   * file.
   *
   * <p>PATHPATTERN supports the Unix shell pattern matching convention for paths (globbing
   * pathnames). Its format may either indicate a path to a single file, or to multiple files with
   * the use of shell-style wildcards (* or ?). To avoid surprising behavior when matching targets
   * with PATHPATTERN, it is RECOMMENDED that PATHPATTERN uses the forward slash (/) as directory
   * separator and does not start with a directory separator, as is also recommended for TARGETPATH.
   * A path separator in a path SHOULD NOT be matched by a wildcard in the PATHPATTERN.
   *
   * <p>Some example PATHPATTERNs and expected matches:
   *
   * <p>"targets/*.tgz" would match file paths "targets/foo.tgz" and "targets/bar.tgz", but not
   * "targets/foo.txt". "foo-version-?.tgz" matches "foo-version-2.tgz" and "foo-version-a.tgz", but
   * not "foo-version-alpha.tgz". "*.tgz" would match "foo.tgz" and "bar.tgz", but not
   * "targets/foo.tgz" "foo.tgz" would match only "foo.tgz"
   */
  List<String> getPaths();

  /** A boolean indicating whether subsequent delegations should be considered. */
  @Gson.Named("terminating")
  boolean isTerminating();

  /**
   * A list of strings, where each string is a hex-encoded hash prefix. Clients MUST check that the
   * SHA-256 hash of the target's name starts with one of these prefixes.
   */
  @Gson.Named("path_hash_prefixes")
  List<String> getPathHashPrefixes();
}
