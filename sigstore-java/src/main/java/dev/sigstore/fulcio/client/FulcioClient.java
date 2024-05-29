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
package dev.sigstore.fulcio.client;

import java.net.URI;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;

/** A client to communicate with a fulcio service instance. */
public interface FulcioClient {
  URI PUBLIC_GOOD_URI = URI.create("https://fulcio.sigstore.dev");
  URI STAGING_URI = URI.create("https://fulcio.sigstage.dev");

  CertPath signingCertificate(CertificateRequest request)
      throws InterruptedException, CertificateException;
}
