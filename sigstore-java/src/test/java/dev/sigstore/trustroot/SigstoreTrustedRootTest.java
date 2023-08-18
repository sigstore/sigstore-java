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
package dev.sigstore.trustroot;

import static org.junit.jupiter.api.AssertionFailureBuilder.assertionFailure;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.proto.trustroot.v1.TrustedRoot;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SigstoreTrustedRootTest {

  private static SigstoreTrustedRoot trustRoot;

  @BeforeAll
  public static void initTrustRoot() throws IOException, CertificateException {
    var json =
        Resources.toString(
            Resources.getResource("dev/sigstore/trustroot/trusted_root.json"),
            StandardCharsets.UTF_8);
    var builder = TrustedRoot.newBuilder();
    JsonFormat.parser().merge(json, builder);

    trustRoot = SigstoreTrustedRoot.from(builder.build());
  }

  @Test
  void from_checkFields() throws Exception {
    assertEquals(2, trustRoot.getCAs().size());
    assertEquals(1, trustRoot.getTLogs().size());
    assertEquals(2, trustRoot.getCTLogs().size());

    var oldCA = trustRoot.getCAs().all().get(0);
    assertEquals("sigstore", oldCA.getSubject().getCommonName());
    assertEquals("sigstore.dev", oldCA.getSubject().getOrganization());
    assertEquals(
        ZonedDateTime.parse("2021-03-07T03:20:29.000Z").toInstant(),
        oldCA.getValidFor().getStart());
    assertEquals(
        ZonedDateTime.parse("2022-12-31T23:59:59.999Z").toInstant(),
        oldCA.getValidFor().getEnd().get());
    assertEquals(
        "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==",
        Base64.toBase64String(oldCA.getCertPath().getCertificates().get(0).getEncoded()));
    assertNotNull(oldCA.getCertPath());

    var currCA = trustRoot.getCAs().all().get(1);
    assertEquals("sigstore", currCA.getSubject().getCommonName());
    assertEquals("sigstore.dev", currCA.getSubject().getOrganization());
    assertEquals(
        ZonedDateTime.parse("2022-04-13T20:06:15.000Z").toInstant(),
        currCA.getValidFor().getStart());
    assertTrue(currCA.getValidFor().getEnd().isEmpty());
    assertEquals(
        "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=",
        Base64.toBase64String(currCA.getCertPath().getCertificates().get(0).getEncoded()));
    assertEquals(
        "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ",
        Base64.toBase64String(currCA.getCertPath().getCertificates().get(1).getEncoded()));
    assertNotNull(currCA.getCertPath());

    var tlog = trustRoot.getTLogs().getTransparencyLogs().get(0);
    assertEquals("https://rekor.sigstore.dev", tlog.getBaseUrl().toString());
    assertEquals("SHA2_256", tlog.getHashAlgorithm());
    assertEquals(
        ZonedDateTime.parse("2021-01-12T11:53:27.000Z").toInstant(),
        tlog.getPublicKey().getValidFor().getStart());
    assertTrue(tlog.getPublicKey().getValidFor().getEnd().isEmpty());
    assertEquals(
        "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
        Base64.toBase64String(tlog.getLogId().getKeyId()));
    assertEquals(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        Base64.toBase64String(tlog.getPublicKey().toJavaPublicKey().getEncoded()));

    var oldCTLog = trustRoot.getCTLogs().all().get(0);
    assertEquals("https://ctfe.sigstore.dev/test", oldCTLog.getBaseUrl().toString());
    assertEquals("SHA2_256", oldCTLog.getHashAlgorithm());
    assertEquals(
        ZonedDateTime.parse("2021-03-14T00:00:00.000Z").toInstant(),
        oldCTLog.getPublicKey().getValidFor().getStart());
    assertEquals(
        ZonedDateTime.parse("2022-10-31T23:59:59.999Z").toInstant(),
        oldCTLog.getPublicKey().getValidFor().getEnd().get());
    assertEquals(
        "CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=",
        Base64.toBase64String(oldCTLog.getLogId().getKeyId()));
    assertEquals(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==",
        Base64.toBase64String(oldCTLog.getPublicKey().toJavaPublicKey().getEncoded()));

    var currCTLog = trustRoot.getCTLogs().all().get(1);
    assertEquals("https://ctfe.sigstore.dev/2022", currCTLog.getBaseUrl().toString());
    assertEquals("SHA2_256", currCTLog.getHashAlgorithm());
    assertEquals(
        ZonedDateTime.parse("2022-10-20T00:00:00.000Z").toInstant(),
        currCTLog.getPublicKey().getValidFor().getStart());
    assertTrue(currCTLog.getPublicKey().getValidFor().getEnd().isEmpty());
    assertEquals(
        "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4=",
        Base64.toBase64String(currCTLog.getLogId().getKeyId()));
    assertEquals(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==",
        Base64.toBase64String(currCTLog.getPublicKey().toJavaPublicKey().getEncoded()));
  }

  @Test
  public void getTlog_isPresent() {
    var key = Base64.decode("wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=");

    // exactly at start time
    assertTLogEntryIsPresent(
        trustRoot.getTLogs()::find, key, ZonedDateTime.parse("2021-01-12T11:53:27.000Z"));
    // other random time
    assertTLogEntryIsPresent(
        trustRoot.getTLogs()::find, key, ZonedDateTime.parse("2021-12-12T11:53:27.000Z"));
  }

  @Test
  public void getTlog_isNotPresent() {
    // before the start time, but valid key
    assertTLogEntryIsEmpty(
        trustRoot.getTLogs()::find,
        Base64.decode("wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="),
        ZonedDateTime.parse("2021-01-01T11:53:27.000Z"));

    // valid time but bad key
    assertTLogEntryIsEmpty(
        trustRoot.getTLogs()::find,
        Base64.decode("wNI8atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="),
        ZonedDateTime.parse("2021-12-12T11:53:27.000Z"));
  }

  @Test
  public void getCurrentTLog() {
    var tlog = trustRoot.getTLogs().current();
    assertArrayEquals(
        Base64.decode("wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="), tlog.getLogId().getKeyId());
  }

  @Test
  public void getCurrentCTLog() {
    var ctlog = trustRoot.getCTLogs().current();
    assertArrayEquals(
        Base64.decode("3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4="), ctlog.getLogId().getKeyId());
  }

  @Test
  public void getCTLog_isPresent() {
    var key = Base64.decode("CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=");

    // exactly at start
    assertTLogEntryIsPresent(
        trustRoot.getCTLogs()::find, key, ZonedDateTime.parse("2021-03-14T00:00:00.000Z"));
    // in the middle
    assertTLogEntryIsPresent(
        trustRoot.getCTLogs()::find, key, ZonedDateTime.parse("2021-10-14T00:00:00.000Z"));
    // exactly at end time
    assertTLogEntryIsPresent(
        trustRoot.getCTLogs()::find, key, ZonedDateTime.parse("2022-10-31T23:59:59.999Z"));
  }

  @Test
  public void getCTLog_isNotPresent() {
    var key = Base64.decode("CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=");

    // before the start time, but valid key
    assertTLogEntryIsEmpty(
        trustRoot.getCTLogs()::find, key, ZonedDateTime.parse("2019-01-01T11:53:27.000Z"));

    // after end time, but valid key
    assertTLogEntryIsEmpty(
        trustRoot.getCTLogs()::find, key, ZonedDateTime.parse("2022-11-01T11:53:27.000Z"));

    // garbage key
    assertTLogEntryIsEmpty(
        trustRoot.getCTLogs()::find,
        Base64.decode("wNI8atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="),
        ZonedDateTime.parse("2021-10-14T00:00:00.000Z"));
  }

  @Test
  public void getCAs_isPresent() {
    // exactly at start
    assertEquals(
        1,
        trustRoot
            .getCAs()
            .find(ZonedDateTime.parse("2021-03-07T03:20:29.000Z").toInstant())
            .size());
    // somewhere in the middle
    assertEquals(
        1,
        trustRoot
            .getCAs()
            .find(ZonedDateTime.parse("2021-04-28T03:59:59.999Z").toInstant())
            .size());
    // exactly at end but also overlapping with another CA
    assertEquals(
        2,
        trustRoot
            .getCAs()
            .find(ZonedDateTime.parse("2022-12-31T23:59:59.999Z").toInstant())
            .size());
  }

  @Test
  public void getCAs_isNotPresent() {
    assertEquals(
        0,
        trustRoot
            .getCAs()
            .find(ZonedDateTime.parse("2015-03-14T00:00:00.000Z").toInstant())
            .size());
  }

  @Test
  public void getCurrentCA() throws CertificateException {
    var ca = trustRoot.getCAs().current();
    List<byte[]> certs = new ArrayList<>(2);
    certs.add(
        0,
        Base64.decode(
            "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="));
    certs.add(
        1,
        Base64.decode(
            "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"));
    var certPath = Certificates.fromDer(certs);
    assertEquals(certPath, ca.getCertPath());
  }

  @FunctionalInterface
  private interface TLogQuery {
    Optional<TransparencyLog> find(byte[] key, Instant time);
  }

  private void assertTLogEntryIsPresent(TLogQuery query, byte[] key, ZonedDateTime time) {
    if (query.find(key, time.toInstant()).isEmpty()) {
      assertionFailure()
          .reason(
              "expected: tlog is found: key_id("
                  + Base64.toBase64String(key)
                  + "), time("
                  + time
                  + ")")
          .buildAndThrow();
    }
  }

  private void assertTLogEntryIsEmpty(TLogQuery query, byte[] key, ZonedDateTime time) {
    if (query.find(key, time.toInstant()).isPresent()) {
      assertionFailure()
          .reason(
              "expected: tlog is not found: key_id("
                  + Base64.toBase64String(key)
                  + "), time("
                  + time
                  + ")")
          .buildAndThrow();
    }
  }
}
