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
package dev.sigstore;

import com.google.common.io.Resources;
import java.io.IOException;
import java.util.List;

/**
 * A temporary partial copy of the TUF repos that supplies necessary keys for prod and staging
 * environments. This should be replaced with an actual TUF implementation
 */
public class VerificationMaterial {

  /** Verification material for *.sigstore.dev */
  public static class Production {
    public static byte[] fulioCert() throws IOException {
      return Resources.toByteArray(
          Resources.getResource("dev/sigstore/tuf/production/fulcio_v1.crt.pem"));
    }

    public static List<byte[]> ctfePublicKeys() throws IOException {
      return List.of(
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/production/ctfe.pub")));
    }

    public static byte[] rekorPublicKey() throws IOException {
      return Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/production/rekor.pub"));
    }
  }

  /** Verification material for *.sigstage.dev */
  public static class Staging {
    public static byte[] fulioCert() throws IOException {
      return Resources.toByteArray(
          Resources.getResource("dev/sigstore/tuf/staging/fulcio.crt.pem"));
    }

    public static List<byte[]> ctfePublicKeys() throws IOException {
      var ctfePublicKey =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/ctfe.pub"));
      var ctfePublicKey2022 =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/ctfe_2022.pub"));
      var ctfePublicKey2022_2 =
          Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/ctfe_2022_2.pub"));
      return List.of(ctfePublicKey, ctfePublicKey2022, ctfePublicKey2022_2);
    }

    public static byte[] rekorPublicKey() throws IOException {
      return Resources.toByteArray(Resources.getResource("dev/sigstore/tuf/staging/rekor.pub"));
    }
  }
}
