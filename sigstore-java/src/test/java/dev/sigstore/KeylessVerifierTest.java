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
package dev.sigstore;

import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.google.gson.JsonParser;
import dev.sigstore.VerificationOptions.CTLogOptions;
import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.VerificationOptions.TLogOptions;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.ImmutableBundle;
import dev.sigstore.encryption.signers.Signers;
import dev.sigstore.rekor.client.RekorTypeException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.strings.StringMatcher;
import dev.sigstore.testing.CertGenerator;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class KeylessVerifierTest {

  @Test
  public void testVerify_noDigestInBundle_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-no-digest.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  @Test
  public void testVerify_mismatchedSet_rekorV1() throws Exception {
    // a bundle file where the SET is replaced with a valid SET for another artifact
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-mismatched-set.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertTrue(
        thrown.getMessage().equals("Transparency log entry could not be verified"));
    Assertions.assertTrue(thrown.getCause() instanceof RekorVerificationException);
    Assertions.assertTrue(thrown.getCause().getMessage().equals("Entry SET was not valid"));
  }

  @Test
  public void testVerify_mismatchedArtifactHash_rekorV1() throws Exception {
    // a bundle file that uses the tlog entry from another artifact signed with the same
    // certificate. The Bundle is fully valid except that the artifact hash doesn't match
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-wrong-tlog-entry.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertTrue(
        thrown
            .getMessage()
            .equals("Provided verification materials are inconsistent with log entry"));
  }

  @Test
  public void testVerify_mismatchedArtifactHash_rekorV2() throws Exception {
    var originalBundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    String originalDigestB64 = "oM/HEnHW4njlfNMy/5V8P3BD/do1TEy7GQow1W76Ab8=";
    String badDigestB64 = "vJJGvv+yDcttb1uHjdvLVmnqDFTtvi/v/3Pvz4Lso0M=";

    var bundle = Bundle.from(new StringReader(originalBundleFile));
    var canonicalizedBodyB64 = bundle.getEntries().get(0).getBody();
    var decodedJson =
        new String(
            java.util.Base64.getDecoder().decode(canonicalizedBodyB64), StandardCharsets.UTF_8);

    var modifiedJson = decodedJson.replace(originalDigestB64, badDigestB64);
    var modifiedB64 =
        java.util.Base64.getEncoder().encodeToString(modifiedJson.getBytes(StandardCharsets.UTF_8));
    var modifiedBundleFile = originalBundleFile.replace(canonicalizedBodyB64, modifiedB64);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(modifiedBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(
        "Artifact digest does not match digest in log entry spec", thrown.getMessage());
  }

  @Test
  public void testVerify_unsupportedDigestAlgorithm_rekorV2() throws Exception {
    var originalBundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    var bundle = Bundle.from(new StringReader(originalBundleFile));
    var canonicalizedBodyB64 = bundle.getEntries().get(0).getBody();
    var decodedJson =
        new String(
            java.util.Base64.getDecoder().decode(canonicalizedBodyB64), StandardCharsets.UTF_8);

    var root = JsonParser.parseString(decodedJson).getAsJsonObject();
    root.getAsJsonObject("spec")
        .getAsJsonObject("hashedRekordV002")
        .getAsJsonObject("data")
        .addProperty("algorithm", "SHA1");
    var modifiedJson = root.toString();
    var modifiedB64 =
        java.util.Base64.getEncoder().encodeToString(modifiedJson.getBytes(StandardCharsets.UTF_8));
    var modifiedBundleFile = originalBundleFile.replace(canonicalizedBodyB64, modifiedB64);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(modifiedBundleFile)),
                    VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(), CoreMatchers.startsWith("Unsupported digest algorithm in log entry"));
  }

  @Test
  public void testVerify_mismatchedSignature_rekorV2() throws Exception {
    var originalBundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    var bundle = Bundle.from(new StringReader(originalBundleFile));
    var canonicalizedBodyB64 = bundle.getEntries().get(0).getBody();
    var decodedJson =
        new String(
            java.util.Base64.getDecoder().decode(canonicalizedBodyB64), StandardCharsets.UTF_8);

    String badSignatureB64 =
        "MEUCIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    var root = JsonParser.parseString(decodedJson).getAsJsonObject();
    root.getAsJsonObject("spec")
        .getAsJsonObject("hashedRekordV002")
        .getAsJsonObject("signature")
        .addProperty("content", badSignatureB64);
    var modifiedJson = root.toString();

    var modifiedB64 =
        java.util.Base64.getEncoder().encodeToString(modifiedJson.getBytes(StandardCharsets.UTF_8));
    var modifiedBundleFile = originalBundleFile.replace(canonicalizedBodyB64, modifiedB64);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(modifiedBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(
        "Signature does not match signature in log entry spec", thrown.getMessage());
  }

  @Test
  public void testVerify_mismatchedCertificate_rekorV2() throws Exception {
    var originalBundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    var bundle = Bundle.from(new StringReader(originalBundleFile));
    var canonicalizedBodyB64 = bundle.getEntries().get(0).getBody();
    var decodedJson =
        new String(
            java.util.Base64.getDecoder().decode(canonicalizedBodyB64), StandardCharsets.UTF_8);

    String badCertB64 =
        "MIICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    var root = JsonParser.parseString(decodedJson).getAsJsonObject();
    root.getAsJsonObject("spec")
        .getAsJsonObject("hashedRekordV002")
        .getAsJsonObject("signature")
        .getAsJsonObject("verifier")
        .getAsJsonObject("x509Certificate")
        .addProperty("rawBytes", badCertB64);
    var modifiedJson = root.toString();

    var modifiedB64 =
        java.util.Base64.getEncoder().encodeToString(modifiedJson.getBytes(StandardCharsets.UTF_8));
    var modifiedBundleFile = originalBundleFile.replace(canonicalizedBodyB64, modifiedB64);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(modifiedBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(
        "Could not parse hashedrekord from log entry body", thrown.getMessage());
    Assertions.assertTrue(thrown.getCause() instanceof RekorTypeException);
    Assertions.assertEquals("Could not parse hashedrekord:0.0.2", thrown.getCause().getMessage());
  }

  @Test
  public void testVerify_badCheckpointSignature_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-bad-checkpoint-signature.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertTrue(
        thrown.getMessage().equals("Transparency log entry could not be verified"));
    Assertions.assertTrue(thrown.getCause() instanceof RekorVerificationException);
    Assertions.assertTrue(
        thrown.getCause().getMessage().equals("Checkpoint signature was invalid"));
  }

  @Test
  public void testVerify_canVerifyV01Bundle_rekorV1() throws Exception {
    // note that this v1 bundle contains an inclusion proof
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v1.sigstore");
  }

  @Test
  public void testVerify_canVerifyV02Bundle_rekorV1() throws Exception {
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v2.sigstore");
  }

  @Test
  public void testVerify_canVerifyV03Bundle_rekorV1() throws Exception {
    verifyBundle(
        "dev/sigstore/samples/bundles/artifact.txt",
        "dev/sigstore/samples/bundles/bundle.v3.sigstore");
  }

  public void verifyBundle(String artifactResourcePath, String bundleResourcePath)
      throws Exception {
    var artifact = Resources.getResource(artifactResourcePath).getPath();
    var bundleFile =
        Resources.toString(Resources.getResource(bundleResourcePath), StandardCharsets.UTF_8);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  @Test
  public void verifyWithVerificationOptions_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact),
        Bundle.from(new StringReader(bundleFile)),
        VerificationOptions.builder()
            .addCertificateMatchers(
                CertificateMatcher.fulcio()
                    .subjectAlternativeName(StringMatcher.string("appu@google.com"))
                    .issuer(StringMatcher.string("https://accounts.google.com"))
                    .build())
            .build());
  }

  @Test
  public void verifyCertificateMatches_noneProvided() throws Exception {
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var certificate =
        (X509Certificate)
            CertGenerator.newCert(
                Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256)
                    .getPublicKey());
    Assertions.assertDoesNotThrow(() -> verifier.checkCertificateMatchers(certificate, List.of()));
  }

  @Test
  public void verifyCertificateMatches_anyOf() throws Exception {
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var certificate =
        (X509Certificate)
            CertGenerator.newCert(
                Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256)
                    .getPublicKey());
    Assertions.assertDoesNotThrow(
        () ->
            verifier.checkCertificateMatchers(
                certificate,
                ImmutableList.of(
                    CertificateMatcher.fulcio()
                        .subjectAlternativeName(StringMatcher.string("not-match"))
                        .issuer(StringMatcher.string("not-match"))
                        .build(),
                    CertificateMatcher.fulcio()
                        .subjectAlternativeName(StringMatcher.string("test@test.com"))
                        .issuer(StringMatcher.string("https://fakeaccounts.test.com"))
                        .build())));
  }

  @Test
  public void verifyCertificateMatches_noneMatch() throws Exception {
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var certificate =
        (X509Certificate)
            CertGenerator.newCert(
                Signers.from(AlgorithmRegistry.SigningAlgorithm.PKIX_ECDSA_P256_SHA_256)
                    .getPublicKey());
    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.checkCertificateMatchers(
                    certificate,
                    ImmutableList.of(
                        CertificateMatcher.fulcio()
                            .subjectAlternativeName(StringMatcher.string("not-match"))
                            .issuer(StringMatcher.string("not-match"))
                            .build(),
                        CertificateMatcher.fulcio()
                            .subjectAlternativeName(StringMatcher.string("not-match-again"))
                            .issuer(StringMatcher.string("not-match-again"))
                            .build())));
    Assertions.assertEquals(
        "No provided certificate identities matched values in certificate: [{issuer:'String:"
            + " not-match',san:'String: not-match'},{issuer:'String: not-match-again',san:'String:"
            + " not-match-again'}]",
        ex.getMessage());
  }

  @Test
  public void testVerify_dsseBundle_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.dsse.sigstore"),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  static Stream<Arguments> badDsseProvider() {
    return Stream.of(
        Arguments.arguments("bundle.dsse.bad-signature.sigstore", "DSSE signature was not valid"),
        Arguments.arguments(
            "bundle.dsse.mismatched-envelope.sigstore",
            "Digest of DSSE payload in bundle does not match DSSE payload digest in log entry"),
        Arguments.arguments(
            "bundle.dsse.mismatched-signature.sigstore",
            "Provided DSSE signature materials are inconsistent with DSSE log entry"),
        Arguments.arguments(
            "bundle.dsse.rekor-v2.bad-signature.sigstore", "DSSE signature was not valid"),
        Arguments.arguments(
            "bundle.dsse.rekor-v2.mismatched-envelope.sigstore",
            "Digest of DSSE.pae in bundle does not match digest in log entry"),
        Arguments.arguments(
            "bundle.dsse.rekor-v2.mismatched-signature.sigstore",
            "Signature in DSSE envelope does not match signature in log entry"),
        Arguments.arguments(
            "bundle.dsse.rekor-v2.bad-entry-type.sigstore",
            "Unsupported entry type: 'dsse:0.0.2' for DSSE bundle"));
  }

  @ParameterizedTest
  @MethodSource("badDsseProvider")
  public void testVerify_dsseBundleInvalid_rekor(String bundleName, String expectedError)
      throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/" + bundleName),
            StandardCharsets.UTF_8);
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var builder = KeylessVerifier.builder();
    if (bundleName.contains("rekor-v2")) {
      builder.sigstoreStagingDefaults();
    } else {
      builder.sigstorePublicDefaults();
    }
    var verifier = builder.build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(expectedError, ex.getMessage());
  }

  @Test
  public void testVerify_dsseBundleArtifactNotInSubjects_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.dsse.sigstore"),
            StandardCharsets.UTF_8);
    var badArtifactDigest =
        Hashing.sha256().hashString("nonsense", StandardCharsets.UTF_8).asBytes();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    badArtifactDigest,
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.startsWith(
            "Provided artifact digest does not match any subject sha256 digests in DSSE payload"));
  }

  @Test
  public void testVerify_noTlogEntries_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-with-timestamp.sigstore"),
            StandardCharsets.UTF_8);
    var baseBundle = Bundle.from(new StringReader(bundleFile));

    var testBundle = ImmutableBundle.builder().from(baseBundle).entries(List.of()).build();

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    // By default a transparency-log entry is required, so a bundle without one is rejected with a
    // clear error (rather than the incidental IndexOutOfBoundsException it used to raise).
    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(Path.of(artifact), testBundle, VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(), CoreMatchers.startsWith("No transparency log entry found"));
  }

  @Test
  public void testVerify_dsseWrongPayloadType_rekorV1() throws Exception {
    var bundleFile =
        Files.readString(
            Path.of(
                Resources.getResource("dev/sigstore/samples/bundles/bundle.dsse.sigstore")
                    .toURI()));

    var invalidBundleFile =
        bundleFile.replace(
            "\"payloadType\": \"application/vnd.in-toto+json\"",
            "\"payloadType\": \"application/json\"");

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(invalidBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(
        "DSSE envelope must have payload type application/vnd.in-toto+json, but found"
            + " 'application/json'",
        ex.getMessage());
  }

  @Test
  public void testVerify_unsupportedRekorVersion_rekorV2() throws Exception {
    var bundleFile =
        Files.readString(
            Path.of(
                Resources.getResource(
                        "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore")
                    .toURI()));

    var invalidBundleFile =
        bundleFile
            .replace("\"version\": \"0.0.2\"", "\"version\": \"0.0.3\"")
            .replace(
                "eyJhcGlWZXJzaW9uIjoiMC4wLjIi", // base64 of '{"apiVersion":"0.0.2"'
                "eyJhcGlWZXJzaW9uIjoiMC4wLjMi"); // base64 of '{"apiVersion":"0.0.3"'

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(invalidBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals("Unsupported hashedrekord version: 0.0.3", ex.getMessage());
  }

  @Test
  public void testVerify_validRfc3161Timestamp() throws Exception {
    var artifactUrl = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt");
    var artifactBytes = Resources.toByteArray(artifactUrl);
    var artifactDigest = Hashing.sha256().hashBytes(artifactBytes).asBytes();

    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-with-timestamp.sigstore"),
            StandardCharsets.UTF_8);
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    Assertions.assertDoesNotThrow(
        () ->
            verifier.verify(
                artifactDigest,
                Bundle.from(new StringReader(bundleFile)),
                VerificationOptions.empty()));
  }

  @Test
  public void testVerify_invalidRfc3161Timestamp() throws Exception {
    var tsRespBytesInvalid =
        Resources.toByteArray(
            Resources.getResource(
                "dev/sigstore/samples/timestamp-response/invalid/sigstore_tsa_response_invalid.tsr"));

    var artifactUrl = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt");
    var artifactBytes = Resources.toByteArray(artifactUrl);
    var artifactDigest = Hashing.sha256().hashBytes(artifactBytes).asBytes();

    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.v3.sigstore"),
            StandardCharsets.UTF_8);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var baseBundle = Bundle.from(new StringReader(bundleFile));
    var testBundle =
        ImmutableBundle.builder()
            .from(baseBundle)
            .timestamps(List.of(createTimestamp(tsRespBytesInvalid)))
            .build();
    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(artifactDigest, testBundle, VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.equalTo(
            "RFC3161 timestamp verification failed: Failed to parse TimeStampResponse"));
  }

  @Test
  public void testVerify_invalidTimestampGenTime() throws Exception {
    var tsRespBytesInvalidGenTime =
        Resources.toByteArray(
            Resources.getResource(
                "dev/sigstore/samples/timestamp-response/valid/sigstore_tsa_response_with_embedded_certs.tsr"));

    var artifactResourcePath = "dev/sigstore/samples/bundles/artifact.txt";
    var artifactBytes = Resources.toByteArray(Resources.getResource(artifactResourcePath));
    var artifactDigest = Hashing.sha256().hashBytes(artifactBytes).asBytes();

    var bundleFileContent =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.v3.sigstore"),
            StandardCharsets.UTF_8);
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var baseBundle = Bundle.from(new StringReader(bundleFileContent));
    var testBundle =
        ImmutableBundle.builder()
            .from(baseBundle)
            .timestamps(List.of(createTimestamp(tsRespBytesInvalidGenTime)))
            .build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(artifactDigest, testBundle, VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.startsWith(
            "RFC3161 timestamp verification failed: Certificate was not verifiable against TSAs"));
  }

  @Test
  public void testVerify_validRfc3161Timestamp_rekorV1() throws Exception {
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();

    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-with-timestamp.sigstore"),
            StandardCharsets.UTF_8);
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    Assertions.assertDoesNotThrow(
        () ->
            verifier.verify(
                Path.of(artifact),
                Bundle.from(new StringReader(bundleFile)),
                VerificationOptions.empty()));
  }

  @Test
  public void testVerify_canVerifyV03Bundle_rekorV2() throws Exception {
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  @Test
  public void testVerify_dsseBundle_rekorV2() throws Exception {
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.dsse.rekor-v2.sigstore"),
            StandardCharsets.UTF_8);

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  @Test
  public void testVerify_dsseBundleArtifactNotInSubjects_rekorV2() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle.dsse.rekor-v2.sigstore"),
            StandardCharsets.UTF_8);
    var badArtifactDigest =
        Hashing.sha256().hashString("nonsense", StandardCharsets.UTF_8).asBytes();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    badArtifactDigest,
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.startsWith(
            "Provided artifact digest does not match any subject sha256 digests in DSSE payload"));
  }

  @Test
  public void testVerify_noRfc3161Timestamps_rekorV2() throws Exception {
    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/bundle-with-rekor-v2-entry.sigstore"),
            StandardCharsets.UTF_8);

    var validRfc3161Timestamps =
        "\"rfc3161Timestamps\": [{\n"
            + "        \"signedTimestamp\":"
            + " \"MIIC1DADAgEAMIICywYJKoZIhvcNAQcCoIICvDCCArgCAQMxDTALBglghkgBZQMEAgEwgcIGCyqGSIb3DQEJEAEEoIGyBIGvMIGsAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgtF/jtMHzKroX8UjkT/BViNcIlC5Y7za/y4n5cjasXD0CFQCxAdEfFrtmTuy4mcW7QjLeeOAUXhgPMjAyNTA3MDIxODUxNTFaMAMCAQECCE0pZTAXtl1eoDKkMDAuMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxFTATBgNVBAMTDHNpZ3N0b3JlLXRzYaAAMYIB2zCCAdcCAQEwUTA5MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIDAeBgNVBAMTF3NpZ3N0b3JlLXRzYS1zZWxmc2lnbmVkAhQKNaEGYdXiQXPGiZan8n3yfgN8pzALBglghkgBZQMEAgGggfwwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTA3MDIxODUxNTFaMC8GCSqGSIb3DQEJBDEiBCCiICYObTnM098xx9niiVyPo+gxp4FTvN94z4K6gH/LgjCBjgYLKoZIhvcNAQkQAi8xfzB9MHsweQQgBvT/4Ef+s1mZtzOw16MjUBz8GOTAM2aoRdd1NudLJ0QwVTA9pDswOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZAIUCjWhBmHV4kFzxomWp/J98n4DfKcwCgYIKoZIzj0EAwIEZzBlAjB0/hfB4Hm4GO5SZYuDzCtgnNdXQkETtx/QTtILM09awUdez2kQNmCAkLtPBf8ojB8CMQDfRBy5WNohfrWNDh0o+NBR7Yj67vsUyBS1WK5nT5QatouJQ3PbtSJN3Kk8xsiVxFc=\"\n"
            + "      }]";
    var noRfc3161Timestamps = "\"rfc3161Timestamps\": []";
    var invalidBundleFile = bundleFile.replace(validRfc3161Timestamps, noRfc3161Timestamps);

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var ex =
        Assertions.assertThrows(
            IllegalStateException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(invalidBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals(
        "No timestamp verification (set, timestamp) was provided", ex.getMessage());
  }

  @Test
  public void testVerify_invalidSet_validRfc3161Timestamp_rekorV1() throws Exception {
    var bundleFileWithTs =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-with-timestamp.sigstore"),
            StandardCharsets.UTF_8);

    var invalidBundleFile =
        bundleFileWithTs.replace(
            "\"integratedTime\": \"1747928754\"", "\"integratedTime\": \"1747928000\"");

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(invalidBundleFile)),
                    VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(), CoreMatchers.equalTo("Transparency log entry could not be verified"));
    MatcherAssert.assertThat(
        ex.getCause().getMessage(), CoreMatchers.equalTo("Entry SET was not valid"));
  }

  private Bundle.Timestamp createTimestamp(byte[] rfc3161Bytes) {
    return () -> rfc3161Bytes;
  }

  @Test
  public void testVerify_certificateExpired_rekorV1() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource("dev/sigstore/samples/bundles/bundle-with-expired-cert.sigstore"),
            StandardCharsets.UTF_8);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertEquals("Signing time was after certificate expiry", ex.getMessage());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ECDSA_P256_SHA_256",
        "ECDSA_P384_SHA_384",
        "ECDSA_P521_SHA_512",
        "RSA_PKCS1V15_2048_SHA256",
        "RSA_PKCS1V15_3072_SHA256",
        "RSA_PKCS1V15_4096_SHA256"
      })
  public void testVerify_algorithmRegistry(String keyAlgorithm) throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/PKIX_" + keyAlgorithm + ".sigstore.json"),
            StandardCharsets.UTF_8);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    verifier.verify(
        Path.of(artifact), Bundle.from(new StringReader(bundleFile)), VerificationOptions.empty());
  }

  @Test
  public void testVerify_wrongArtifactHashAlgorithm() throws Exception {
    var bundleFile =
        Resources.toString(
            Resources.getResource(
                "dev/sigstore/samples/bundles/PKIX_ECDSA_P256_SHA_256.sigstore.json"),
            StandardCharsets.UTF_8);

    var artifact = Resources.getResource("dev/sigstore/samples/bundles/artifact.txt").getPath();
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();

    var sha512 = Hashing.sha512().hashBytes(Files.readAllBytes(Path.of(artifact))).asBytes();

    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    sha512,
                    Bundle.from(new StringReader(bundleFile)),
                    VerificationOptions.empty()));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.startsWith(
            "Provided artifact digest does not match digest used for verification"));
  }

  // The fixture below is a real SLSA build-provenance attestation produced by GitHub Actions for a
  // *private* repository. Attestations for private repositories are signed by GitHub's own Sigstore
  // instance, which (unlike the public-good instance) does not publish to a transparency log and
  // does not use certificate transparency: the bundle carries zero tlog entries and relies on a
  // signed RFC 3161 timestamp for trusted time, and the trust root that GitHub distributes for it
  // (via `gh attestation trusted-root`) contains zero CT logs. Verifying such a bundle therefore
  // requires a policy that disables both transparency-log and certificate-transparency checks.
  //
  // The zip file contains two files:
  //   - attestation.sigstore.json : the sigstore bundle (DSSE, in-toto SLSA provenance predicate)
  //   - trusted_root.jsonl        : the trust roots as JSON Lines. `gh attestation trusted-root`
  //                                 emits more than one (public-good and GitHub); sigstore-java
  //                                 consumes a single trust root, so the tests below select the
  //                                 GitHub one (the line describing the fulcio.githubapp.com CA).
  private static final String GH_PRIVATE_ATTESTATION_ZIP =
      "dev/sigstore/samples/bundles/bundle-github-private-no-tlog.zip";
  private static final String GH_PRIVATE_SIGNER_SAN =
      "https://github.com/neverendingsupport/slsa-attestations/.github/workflows/attest.yml@9f6d9dc1bfc02986955721eb15f89ad618f1cedb";
  private static final String GH_PRIVATE_OIDC_ISSUER =
      "https://token.actions.githubusercontent.com";
  // sha256 of one of the artifacts recorded as a subject in the attestation.
  private static final String GH_PRIVATE_SUBJECT_SHA256 =
      "caa015ef69e9bc31a41322d6c71563ed9600c75bb988e4d639b1edc578580551";

  @Test
  public void testVerify_noTransparencyLog_gitHubPrivateInstance(@TempDir Path tempDir)
      throws Exception {
    var bundle = gitHubPrivateBundle();
    var verifier = gitHubPrivateVerifier(tempDir);
    var options =
        gitHubPrivateOptions()
            .addCertificateMatchers(
                CertificateMatcher.fulcio()
                    .subjectAlternativeName(StringMatcher.string(GH_PRIVATE_SIGNER_SAN))
                    .issuer(StringMatcher.string(GH_PRIVATE_OIDC_ISSUER))
                    .build())
            .build();

    Assertions.assertDoesNotThrow(
        () ->
            verifier.verify(
                BaseEncoding.base16().lowerCase().decode(GH_PRIVATE_SUBJECT_SHA256),
                bundle,
                options));
  }

  @Test
  public void testVerify_noTransparencyLog_rejectedWithoutOptIn(@TempDir Path tempDir)
      throws Exception {
    var bundle = gitHubPrivateBundle();
    var verifier = gitHubPrivateVerifier(tempDir);

    // Default options do not permit skipping the transparency log, so the bundle is rejected.
    Assertions.assertThrows(
        KeylessVerificationException.class,
        () ->
            verifier.verify(
                BaseEncoding.base16().lowerCase().decode(GH_PRIVATE_SUBJECT_SHA256),
                bundle,
                VerificationOptions.empty()));
  }

  @Test
  public void testVerify_noTransparencyLog_optInStillChecksArtifactDigest(@TempDir Path tempDir)
      throws Exception {
    var bundle = gitHubPrivateBundle();
    var verifier = gitHubPrivateVerifier(tempDir);
    var options = gitHubPrivateOptions().build();

    // Relaxing the tlog/CT requirements does not relax the rest: the artifact digest must still be
    // one of the attested subjects.
    var badArtifactDigest =
        Hashing.sha256().hashString("nonsense", StandardCharsets.UTF_8).asBytes();
    var ex =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(badArtifactDigest, bundle, options));
    MatcherAssert.assertThat(
        ex.getMessage(),
        CoreMatchers.startsWith(
            "Provided artifact digest does not match any subject sha256 digests in DSSE payload"));
  }

  // A private-deployment policy: neither a transparency-log entry nor an SCT is required.
  private static ImmutableVerificationOptions.Builder gitHubPrivateOptions() {
    return VerificationOptions.builder()
        .tLogOptions(TLogOptions.builder().isEnabled(false).build())
        .ctLogOptions(CTLogOptions.builder().isEnabled(false).build());
  }

  private static Bundle gitHubPrivateBundle() throws Exception {
    return Bundle.from(
        new StringReader(
            new String(
                readZipEntry(GH_PRIVATE_ATTESTATION_ZIP, "attestation.sigstore.json"),
                StandardCharsets.UTF_8)));
  }

  private static KeylessVerifier gitHubPrivateVerifier(Path tempDir) throws Exception {
    var jsonl =
        new String(
            readZipEntry(GH_PRIVATE_ATTESTATION_ZIP, "trusted_root.jsonl"), StandardCharsets.UTF_8);
    var gitHubTrustedRoot =
        jsonl
            .lines()
            .filter(line -> line.contains("fulcio.githubapp.com"))
            .findFirst()
            .orElseThrow(
                () ->
                    new IllegalStateException("no GitHub trust root found in trusted_root.jsonl"));
    var trustedRootPath = tempDir.resolve("github-trusted-root.json");
    Files.writeString(trustedRootPath, gitHubTrustedRoot);
    return KeylessVerifier.builder()
        .trustedRootProvider(TrustedRootProvider.from(trustedRootPath))
        .build();
  }

  private static byte[] readZipEntry(String zipResource, String entryName) throws Exception {
    try (var zis = new ZipInputStream(Resources.getResource(zipResource).openStream())) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        if (entry.getName().equals(entryName)) {
          return zis.readAllBytes();
        }
      }
    }
    throw new IllegalStateException("entry '" + entryName + "' not found in " + zipResource);
  }
}
