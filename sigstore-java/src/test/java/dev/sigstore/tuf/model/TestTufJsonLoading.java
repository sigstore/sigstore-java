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
package dev.sigstore.tuf.model;

import static dev.sigstore.json.GsonSupplier.GSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.google.common.io.Resources;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class TestTufJsonLoading {

  @Test
  public void loadRootJson() throws IOException {
    Root trustRoot;
    try (Reader reader =
        Resources.asCharSource(
                Resources.getResource("dev/sigstore/tuf/sigstore-tuf-root/root.json"),
                Charset.defaultCharset())
            .openStream(); ) {
      trustRoot = GSON.get().fromJson(reader, Root.class);
    }
    assertNotNull(trustRoot);
    assertEquals(5, trustRoot.getSignatures().size());
    Signature signature = trustRoot.getSignatures().get(0);
    assertNotNull(signature);
    assertEquals(
        "2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97", signature.getKeyId());
    assertEquals(
        "3046022100f7d4abde3d694fba01af172466629249a6743efd04c3999f958494842a7aee1f022100d19a295f9225247f17650fdb4ad50b99c2326700aadd0afaec4ae418941c7c59",
        trustRoot.getSignatures().get(0).getSignature());
    RootMeta signedMeta = trustRoot.getSignedMeta();
    assertNotNull(signedMeta);
    assertEquals(false, signedMeta.getConsistentSnapshot());
    assertEquals("2023-01-12T18:22:02Z", signedMeta.getExpires());
    assertEquals(7, signedMeta.getKeys().entrySet().size());
    Key key =
        signedMeta
            .getKeys()
            .get("2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97");
    assertNotNull(key);
    assertEquals(2, key.getKeyIdHashAlgorithms().size());
    assertEquals("ecdsa-sha2-nistp256", key.getKeyType());
    assertEquals(
        "04cbc5cab2684160323c25cd06c3307178a6b1d1c9b949328453ae473c5ba7527e35b13f298b41633382241f3fd8526c262d43b45adee5c618fa0642c82b8a9803",
        key.getKeyVal().get("public"));
    assertEquals("ecdsa-sha2-nistp256", key.getScheme());
  }

  @Test
  public void loadSnapshotJson() throws IOException {
    Snapshot snapshot;
    try (Reader reader =
        Resources.asCharSource(
                Resources.getResource("dev/sigstore/tuf/sigstore-tuf-root/snapshot.json"),
                Charset.defaultCharset())
            .openStream(); ) {
      snapshot = GSON.get().fromJson(reader, Snapshot.class);
    }
    assertNotNull(snapshot);
    assertEquals(1, snapshot.getSignatures().size());
    assertEquals(
        "fc61191ba8a516fe386c7d6c97d918e1d241e1589729add09b122725b8c32451",
        snapshot.getSignatures().get(0).getKeyId());
    assertEquals(
        "304502202c64259b34ce58411d61d5ced5165bddc2e004e5374e558884deadc1f60dbba3022100a9055dce3d8da1a8f1423d63735bac980aa9afdac71425008b89818530c17173",
        snapshot.getSignatures().get(0).getSignature());
    SnapshotMeta meta = snapshot.getSignedMeta();
    assertNotNull(meta);
    assertEquals("1.0", meta.getSpecVersion());
    assertEquals(41, meta.getVersion());
    Map<String, SnapshotMeta.SnapshotTarget> metaValues = meta.getMeta();
    assertNotNull(metaValues);
    assertEquals(5, metaValues.size());
    SnapshotMeta.SnapshotTarget rekorSnapshot = metaValues.get("rekor.json");
    assertNotNull(rekorSnapshot);
    assertNotNull(rekorSnapshot.getHashes());
    assertEquals(
        "9d2e1a5842937d8e0d3e3759170b0ad15c56c5df36afc5cf73583ddd283a463b",
        rekorSnapshot.getHashes().getSha256());
    assertEquals(
        "176e9e710ddddd1b357a7d7970831bae59763395a0c18976110cbd35b25e5412dc50f356ec421a7a30265670cf7aec9ed84ee944ba700ec2394b9c876645b960",
        rekorSnapshot.getHashes().getSha512());
    assertEquals(797, rekorSnapshot.getLength());
    assertEquals(3, rekorSnapshot.getVersion());
  }

  @Test
  public void loadTargetsJson() throws IOException {
    Targets targets;
    try (Reader reader =
        Resources.asCharSource(
                Resources.getResource("dev/sigstore/tuf/sigstore-tuf-root/targets.json"),
                Charset.defaultCharset())
            .openStream(); ) {
      targets = GSON.get().fromJson(reader, Targets.class);
    }
    assertNotNull(targets);
    assertEquals(5, targets.getSignatures().size());
    assertEquals(
        "2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97",
        targets.getSignatures().get(0).getKeyId());
    assertEquals(
        "3044022100d54e28736b8ac066410aa4b1560b2244d1c631a8b0192420c34e2db07248ed54021f1193d7e7ecbb0045533ce912f7685fc66cff42a80b56b3e1e7245c6c542bf1",
        targets.getSignatures().get(0).getSignature());
    TargetMeta signedMeta = targets.getSignedMeta();
    assertEquals("2023-01-12T18:22:03Z", signedMeta.getExpires());
    assertEquals(ZonedDateTime.parse("2023-01-12T18:22:03Z"), signedMeta.getExpiresAsDate());
    assertEquals("1.0", signedMeta.getSpecVersion());
    assertEquals(4, signedMeta.getVersion());
    Delegations delegations = signedMeta.getDelegations().get();
    assertNotNull(delegations);
    Map<String, Key> keys = delegations.getKeys();
    assertEquals(3, keys.size());
    Key key =
        delegations
            .getKeys()
            .get("9e7d813e8e16062e60a4540346aa8e7c7782afb7098af0b944ea80a4033a176f");
    assertNotNull(key);
    assertEquals(2, key.getKeyIdHashAlgorithms().size());
    assertEquals("ecdsa-sha2-nistp256", key.getKeyType());
    assertEquals(
        "042e5916fa6da3d05086e760576bf07e2b9c8bf624f38ab6697b449979d0bc3276baf9021200afd6072ed751d974dbcc93ead6cd749e11cecaf2a5b210a1180af1",
        key.getKeyVal().get("public"));
    assertEquals("ecdsa-sha2-nistp256", key.getScheme());
    List<DelegationRole> roles = delegations.getRoles();
    assertNotNull(roles);
    DelegationRole delegationRole = roles.get(0);
    assertEquals(1, delegationRole.getKeyids().size());
    assertEquals(
        "ae0c689c6347ada7359df48934991f4e013193d6ddf3482a5ffb293f74f3b217",
        delegationRole.getKeyids().get(0));
    assertEquals("rekor", delegationRole.getName());
    assertEquals(1, delegationRole.getPaths().size());
    assertEquals("rekor.*.pub", delegationRole.getPaths().get(0));
    assertEquals(true, delegationRole.isTerminating());
    assertEquals(1, delegationRole.getThreshold());
    Map<String, TargetMeta.TargetData> metaTargets = signedMeta.getTargets();
    assertNotNull(metaTargets);
    TargetMeta.TargetData targetData = metaTargets.get("fulcio.crt.pem");
    assertNotNull(targetData);
    TargetMeta.Custom custom = targetData.getCustom().get();
    assertNotNull(custom);
    assertEquals("Expired", custom.getSigstoreMeta().getStatus());
    assertEquals("Fulcio", custom.getSigstoreMeta().getUsage());
    assertEquals(
        "f360c53b2e13495a628b9b8096455badcb6d375b185c4816d95a5d746ff29908",
        targetData.getHashes().getSha256());
    assertEquals(
        "0713252a7fd17f7f3ab12f88a64accf2eb14b8ad40ca711d7fe8b4ecba3b24db9e9dffadb997b196d3867b8f9ff217faf930d80e4dab4e235c7fc3f07be69224",
        targetData.getHashes().getSha512());
    assertEquals(744, targetData.getLength());
  }
}
