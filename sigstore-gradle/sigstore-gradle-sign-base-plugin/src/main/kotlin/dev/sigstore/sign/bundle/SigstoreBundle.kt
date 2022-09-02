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
 *
 */
package dev.sigstore.sign.bundle

import com.fasterxml.jackson.annotation.JsonPropertyOrder
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer
import dev.sigstore.sign.work.HexStringSerializer

enum class HashAlgorithm {
    sha256
}

@JsonPropertyOrder(
    "algorithm",
    "hash"
)
class HashValue(
    val algorithm: HashAlgorithm,
    @get:JsonSerialize(using = HexStringSerializer::class)
    val hash: ByteArray,
)

interface Attestation

@JsonPropertyOrder(
    "payloadHash",
    "signature",
)
class AttestationBlob(
    val payloadHash: HashValue,
    val signature: ByteArray
) : Attestation

interface TimestampProof

@JsonPropertyOrder(
    "logIndex",
    "logId",
    "kind",
    "version",
    "signedEntryTimestamp",
    "integratedTime",
)
class RekorEntry(
    @get:JsonSerialize(using = ToStringSerializer::class)
    val logIndex: Long,
    val logId: String,
    @get:JsonSerialize(using = ToStringSerializer::class)
    val integratedTime: Long,
    val signedEntryTimestamp: ByteArray,
) : TimestampProof

interface VerificationMaterial

class PublicKeyVerificationMaterial(
    val keyId: String,
) : VerificationMaterial

class X509CertVerificationMaterial(
    val chain: ByteArray
) : VerificationMaterial

@JsonPropertyOrder(
    "mediaType",
    "timestampProof",
    "verificationMaterial",
    "attestation",
)
class SigstoreBundle(
    val mediaType: String,
    val timestampProof: TimestampProof,
    val verificationMaterial: VerificationMaterial,
    val attestation: Attestation,
)

enum class BundleMediaTypes(val value: String) {
    V1_JSON("application/vnd.dev.sigstore.bundle.v1+json")
}
