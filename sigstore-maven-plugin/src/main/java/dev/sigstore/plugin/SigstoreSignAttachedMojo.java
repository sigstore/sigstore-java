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

import dev.sigstore.KeylessSigner;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.encryption.certificates.Certificates;
import java.io.File;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.gpg.FilesCollector;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.codehaus.plexus.util.FileUtils;

/** Sign project artifact, the POM, and attached artifacts with sigstore for deployment. */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SigstoreSignAttachedMojo extends AbstractMojo {

  private static final String BUNDLE_EXTENSION = ".sigstore.json";

  // TODO: this can potentially be derived from mvn-gpg-plugin:FilesCollector.java,
  //   but that requires a change in that plugin before it makes sense here.
  private static final String DEFAULT_EXCLUDES[] =
      new String[] {
        "**/*.md5", "**/*.sha1", "**/*.sha256", "**/*.sha512", "**/*.asc", "**/*.sigstore.json"
      };

  /** Skip doing the sigstore signing. */
  @Parameter(property = "sigstore.skip", defaultValue = "false")
  private boolean skip;

  /**
   * A list of files to exclude from being signed. Can contain Ant-style wildcards and double
   * wildcards. The default excludes are <code>
   * **&#47;*.md5 **&#47;*.sha1 **&#47;*.sha256 **&#47;*.sha512 **&#47;*.asc **&#47;*.sigstore.json
   * </code>.
   */
  @Parameter private String[] excludes;

  /** Use public staging {@code sigstage.dev} instead of public default {@code sigstore.dev}. */
  @Parameter(defaultValue = "false", property = "public-staging")
  private boolean publicStaging;

  /** The Maven project. */
  @Parameter(defaultValue = "${project}", readonly = true)
  private MavenProject project;

  /** Maven ProjectHelper */
  @Component private MavenProjectHelper projectHelper;

  @Override
  public void execute() throws MojoExecutionException, MojoFailureException {
    if (skip) {
      // We're skipping the signing stuff
      return;
    }

    // ----------------------------------------------------------------------------
    // Collect files to sign
    // ----------------------------------------------------------------------------

    FilesCollector collector =
        new FilesCollector(project, (excludes == null) ? DEFAULT_EXCLUDES : excludes, getLog());
    List<FilesCollector.Item> items = collector.collect();

    // ----------------------------------------------------------------------------
    // Sign the filesToSign and attach all the signatures
    // ----------------------------------------------------------------------------

    getLog().info("Signing " + items.size() + " file" + ((items.size() > 1) ? "s" : "") + ".");

    try {
      KeylessSigner signer;

      if (publicStaging) {
        signer = KeylessSigner.builder().sigstoreStagingDefaults().build();
      } else {
        signer = KeylessSigner.builder().sigstorePublicDefaults().build();
      }

      X509Certificate prevCert = null;
      for (FilesCollector.Item item : items) {
        File fileToSign = item.getFile();

        getLog().info("Signing " + fileToSign);
        long start = System.currentTimeMillis();
        Bundle bundle = signer.signFile(fileToSign.toPath());

        X509Certificate cert = (X509Certificate) bundle.getCertPath().getCertificates().get(0);
        if (!cert.equals(prevCert)) {
          prevCert = cert;
          long durationMinutes = Certificates.validity(cert, ChronoUnit.MINUTES);

          getLog()
              .info(
                  "  Fulcio certificate (valid for "
                      + durationMinutes
                      + " m) obtained for "
                      + cert.getSubjectAlternativeNames().iterator().next().get(1)
                      + " (by "
                      + FulcioOidHelper.getIssuerV2(cert)
                      + " IdP)");
        }

        File bundleFile = new File(fileToSign + BUNDLE_EXTENSION);
        FileUtils.fileWrite(bundleFile, "UTF-8", bundle.toJson());

        long duration = System.currentTimeMillis() - start;
        getLog()
            .info(
                "  > Rekor entry "
                    + bundle.getEntries().get(0).getLogIndex()
                    + " obtained in "
                    + duration
                    + " ms, saved to "
                    + bundleFile.getName());

        projectHelper.attachArtifact(
            project, item.getExtension() + BUNDLE_EXTENSION, item.getClassifier(), bundleFile);
      }
    } catch (Exception e) {
      throw new MojoExecutionException("Error while signing with sigstore", e);
    }
  }
}
