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
package dev.sigstore.bundle;

import com.google.protobuf.Descriptors;
import com.google.protobuf.MessageOrBuilder;
import dev.sigstore.proto.bundle.v1.Bundle;
import java.util.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Collect all the required fields reachable from Bundle. It helps to catch if new required fields
 * are added to the Bundle.
 */
public class AllRequiredFieldsInBundleTest {
  static class MessageAndFields {
    private final Descriptors.Descriptor descriptor;
    private final List<Descriptors.GenericDescriptor> fields;

    public MessageAndFields(
        Descriptors.Descriptor descriptor, List<Descriptors.GenericDescriptor> fields) {
      this.descriptor = descriptor;
      this.fields = fields;
    }

    @Override
    public String toString() {
      return descriptor.getFullName()
          + "\n"
          + fields.stream()
              .map(Descriptors.GenericDescriptor::getName)
              .collect(Collectors.joining("\n    ", "    ", ""));
    }
  }

  @Test
  void allRequiredFieldsInBundle() {
    var messages = new LinkedHashMap<Descriptors.Descriptor, MessageAndFields>();
    var seen = new HashSet<Descriptors.Descriptor>();
    collectRequiredFields(Bundle.getDescriptor(), messages, seen);
    String str =
        messages.values().stream().map(Object::toString).collect(Collectors.joining("\n\n"));

    Assertions.assertEquals(
        """
        dev.sigstore.common.v1.X509Certificate
            raw_bytes

        dev.sigstore.common.v1.LogId
            key_id

        dev.sigstore.rekor.v1.KindVersion
            kind
            version

        dev.sigstore.rekor.v1.InclusionPromise
            signed_entry_timestamp

        dev.sigstore.rekor.v1.Checkpoint
            envelope

        dev.sigstore.rekor.v1.InclusionProof
            log_index
            root_hash
            tree_size
            hashes
            checkpoint

        dev.sigstore.rekor.v1.TransparencyLogEntry
            log_index
            log_id
            kind_version
            integrated_time
            inclusion_proof

        dev.sigstore.common.v1.RFC3161SignedTimestamp
            signed_timestamp

        dev.sigstore.bundle.v1.VerificationMaterial
            content

        dev.sigstore.common.v1.MessageSignature
            signature

        dev.sigstore.bundle.v1.Bundle
            verification_material
            content""",
        str,
        "List of all the required fields reachable from Bundle. "
            + "If you see a test failure here (e.g. new required field is added), then "
            + " it you might probably need to account the changes in BundleFactory");
  }

  /**
   * Fetch all the messages that have required fields. It will return all the messages reachable
   * from the given root.
   *
   * <p>Note: the implementation resembles {@link
   * BundleVerifier#findMissingFields(MessageOrBuilder)}, however, the difference is that this
   * method finds all the required fields of all the messages, while {@link
   * BundleVerifier#findMissingFields(MessageOrBuilder)} verifies an actual given message
   *
   * @see BundleVerifier#findMissingFields(MessageOrBuilder)
   */
  private void collectRequiredFields(
      Descriptors.Descriptor descriptor,
      Map<Descriptors.Descriptor, MessageAndFields> messages,
      Set<Descriptors.Descriptor> seen) {
    seen.add(descriptor);
    var fields = new ArrayList<Descriptors.GenericDescriptor>();
    for (Descriptors.FieldDescriptor field : descriptor.getFields()) {
      if (field.getJavaType() == Descriptors.FieldDescriptor.JavaType.MESSAGE) {
        // Drill down into the message
        var messageType = field.getMessageType();
        if (!seen.contains(messageType)) {
          collectRequiredFields(messageType, messages, seen);
        }
      }
      if (!BundleVerifier.isRequired(field)) {
        continue;
      }
      if (field.getContainingOneof() == null) {
        // Remember the field is required
        fields.add(field);
      }
    }
    for (Descriptors.OneofDescriptor oneof : descriptor.getRealOneofs()) {
      if (oneof.getFields().stream().anyMatch(BundleVerifier::isRequired)) {
        fields.add(oneof);
      }
    }
    if (!fields.isEmpty()) {
      messages.put(descriptor, new MessageAndFields(descriptor, fields));
    }
  }
}
