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
package dev.sigstore.proto;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.encryption.certificates.Certificates;
import dev.sigstore.proto.common.v1.HashAlgorithm;
import dev.sigstore.proto.common.v1.X509Certificate;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ProtoMutators {

  public static CertPath toCertPath(List<X509Certificate> certificates)
      throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> converted = new ArrayList<>(certificates.size());
    for (var cert : certificates) {
      converted.add(Certificates.fromDer(cert.getRawBytes().toByteArray()));
    }
    return cf.generateCertPath(converted);
  }

  public static Instant toInstant(Timestamp timestamp) {
    return Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos());
  }

  public static X509Certificate fromCert(java.security.cert.X509Certificate certificate)
      throws CertificateEncodingException {
    byte[] encoded;
    encoded = certificate.getEncoded();
    return X509Certificate.newBuilder().setRawBytes(ByteString.copyFrom(encoded)).build();
  }

  public static HashAlgorithm from(Bundle.HashAlgorithm algorithm) {
    if (algorithm == Bundle.HashAlgorithm.SHA2_256) {
      return HashAlgorithm.SHA2_256;
    }
    throw new IllegalStateException("Unknown hash algorithm: " + algorithm);
  }
}
