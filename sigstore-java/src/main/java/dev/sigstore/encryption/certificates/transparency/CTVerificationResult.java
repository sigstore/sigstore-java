/*
 * Copyright 2022 The Sigstore Authors.
 * Copyright 2015 The Android Open Source Project.
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
package dev.sigstore.encryption.certificates.transparency;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CTVerificationResult {
  private final ArrayList<VerifiedSCT> validSCTs = new ArrayList<VerifiedSCT>();
  private final ArrayList<VerifiedSCT> invalidSCTs = new ArrayList<VerifiedSCT>();

  public void add(VerifiedSCT result) {
    if (result.status == VerifiedSCT.Status.VALID) {
      validSCTs.add(result);
    } else {
      invalidSCTs.add(result);
    }
  }

  public List<VerifiedSCT> getValidSCTs() {
    return Collections.unmodifiableList(validSCTs);
  }

  public List<VerifiedSCT> getInvalidSCTs() {
    return Collections.unmodifiableList(invalidSCTs);
  }
}
