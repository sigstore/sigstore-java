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
import com.google.common.io.Resources;
import com.google.gson.JsonParser;
import dev.sigstore.VerificationOptions.CertificateMatcher;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.ImmutableBundle;
import dev.sigstore.encryption.signers.Signers;
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
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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

    var thrown =
        Assertions.assertThrows(
            KeylessVerificationException.class,
            () ->
                verifier.verify(
                    Path.of(artifact),
                    Bundle.from(new StringReader(modifiedBundleFile)),
                    VerificationOptions.empty()));
    Assertions.assertTrue(
        thrown.getMessage().startsWith("Unsupported digest algorithm in log entry: "));
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
        "No provided certificate identities matched values in certificate: [{issuer:'String: not-match',san:'String: not-match'},{issuer:'String: not-match-again',san:'String: not-match-again'}]",
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
            "bundle.dsse.rekor-v2.mismatched-payload.sigstore",
            "Digest of DSSE payload in bundle does not match DSSE payload digest in log entry"),
        Arguments.arguments(
            "bundle.dsse.rekor-v2.mismatched-signature.sigstore",
            "Signature in DSSE envelope does not match signature in log entry spec"));
  }

  @ParameterizedTest
  @MethodSource("badDsseProvider")
  public void testVerify_dsseBundleInvalid(String bundleName, String expectedError)
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

    Assertions.assertThrows(
        IndexOutOfBoundsException.class,
        () -> verifier.verify(Path.of(artifact), testBundle, VerificationOptions.empty()));
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
        "DSSE envelope must have payload type application/vnd.in-toto+json, but found 'application/json'",
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

    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
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
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();

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
            + "        \"signedTimestamp\": \"MIIC1DADAgEAMIICywYJKoZIhvcNAQcCoIICvDCCArgCAQMxDTALBglghkgBZQMEAgEwgcIGCyqGSIb3DQEJEAEEoIGyBIGvMIGsAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgtF/jtMHzKroX8UjkT/BViNcIlC5Y7za/y4n5cjasXD0CFQCxAdEfFrtmTuy4mcW7QjLeeOAUXhgPMjAyNTA3MDIxODUxNTFaMAMCAQECCE0pZTAXtl1eoDKkMDAuMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxFTATBgNVBAMTDHNpZ3N0b3JlLXRzYaAAMYIB2zCCAdcCAQEwUTA5MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIDAeBgNVBAMTF3NpZ3N0b3JlLXRzYS1zZWxmc2lnbmVkAhQKNaEGYdXiQXPGiZan8n3yfgN8pzALBglghkgBZQMEAgGggfwwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTA3MDIxODUxNTFaMC8GCSqGSIb3DQEJBDEiBCCiICYObTnM098xx9niiVyPo+gxp4FTvN94z4K6gH/LgjCBjgYLKoZIhvcNAQkQAi8xfzB9MHsweQQgBvT/4Ef+s1mZtzOw16MjUBz8GOTAM2aoRdd1NudLJ0QwVTA9pDswOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZAIUCjWhBmHV4kFzxomWp/J98n4DfKcwCgYIKoZIzj0EAwIEZzBlAjB0/hfB4Hm4GO5SZYuDzCtgnNdXQkETtx/QTtILM09awUdez2kQNmCAkLtPBf8ojB8CMQDfRBy5WNohfrWNDh0o+NBR7Yj67vsUyBS1WK5nT5QatouJQ3PbtSJN3Kk8xsiVxFc=\"\n"
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
}
