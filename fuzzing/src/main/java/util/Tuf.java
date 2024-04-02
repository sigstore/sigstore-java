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
package util;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.common.hash.Hashing;
import dev.sigstore.trustroot.CertificateAuthority;
import dev.sigstore.trustroot.ImmutableCertificateAuthority;
import dev.sigstore.trustroot.ImmutableLogId;
import dev.sigstore.trustroot.ImmutablePublicKey;
import dev.sigstore.trustroot.ImmutableSubject;
import dev.sigstore.trustroot.ImmutableTransparencyLog;
import dev.sigstore.trustroot.ImmutableValidFor;
import dev.sigstore.trustroot.TransparencyLog;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class Tuf {

  // arbitrarily decided max certificate size in bytes
  private static final int MAX_CERT_SIZE = 10240;

  // ecdsa key size in bytes
  private static final int ECDSA_KEY_BYTES = 91;

  public static List<TransparencyLog> transparencyLogsFrom(FuzzedDataProvider data) {
    return List.of(genTlog(data));
  }

  public static List<CertificateAuthority> certificateAuthoritiesFrom(FuzzedDataProvider data)
      throws CertificateException {
    return List.of(genCA(data));
  }

  private static CertPath genCertPath(FuzzedDataProvider data) throws CertificateException {
    List<Certificate> certList = new ArrayList<>();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    certList.add(
        cf.generateCertificate(new ByteArrayInputStream(data.consumeBytes(MAX_CERT_SIZE))));
    certList.add(
        cf.generateCertificate(new ByteArrayInputStream(data.consumeBytes(MAX_CERT_SIZE))));
    return cf.generateCertPath(certList);
  }

  private static CertificateAuthority genCA(FuzzedDataProvider data) throws CertificateException {
    return ImmutableCertificateAuthority.builder()
        .validFor(ImmutableValidFor.builder().start(Instant.EPOCH).build())
        .subject(ImmutableSubject.builder().commonName("test").organization("test").build())
        .certPath(genCertPath(data))
        .uri(URI.create("test"))
        .build();
  }

  private static TransparencyLog genTlog(FuzzedDataProvider data) {
    var pk =
        ImmutablePublicKey.builder()
            .keyDetails("PKIX_ECDSA_P256_SHA_256")
            .rawBytes(data.consumeBytes(ECDSA_KEY_BYTES))
            .validFor(ImmutableValidFor.builder().start(Instant.EPOCH).build())
            .build();
    var logId = Hashing.sha256().hashBytes(pk.getRawBytes()).asBytes();
    return ImmutableTransparencyLog.builder()
        .baseUrl(URI.create("test"))
        .hashAlgorithm("SHA2_256")
        .publicKey(pk)
        .logId(ImmutableLogId.builder().keyId(logId).build())
        .build();
  }
}
