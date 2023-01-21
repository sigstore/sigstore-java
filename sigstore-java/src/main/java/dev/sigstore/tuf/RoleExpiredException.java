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
package dev.sigstore.tuf;

import java.time.ZonedDateTime;

/**
 * Thrown when the local trusted role is expired and no valid un-expired new role is found on the
 * remote mirror. TODO: add role type to exception message.
 */
public class RoleExpiredException extends TufException {
  private String mirrorUrl;
  private ZonedDateTime updateTime;
  private ZonedDateTime roleExpirationTime;

  public RoleExpiredException(
      String mirrorUrl, ZonedDateTime updateTime, ZonedDateTime roleExpirationTime) {
    super(
        String.format(
            "Trusted metadata is expired but no new versions are available at the "
                + "mirror URL:(%s)\n update start time: %tc\n expired time: %tc)",
            mirrorUrl, updateTime, roleExpirationTime));
    this.mirrorUrl = mirrorUrl;
    this.updateTime = updateTime;
    this.roleExpirationTime = roleExpirationTime;
  }

  public String getMirrorUrl() {
    return mirrorUrl;
  }

  public ZonedDateTime getUpdateTime() {
    return updateTime;
  }

  public ZonedDateTime getRoleExpirationTime() {
    return roleExpirationTime;
  }
}
