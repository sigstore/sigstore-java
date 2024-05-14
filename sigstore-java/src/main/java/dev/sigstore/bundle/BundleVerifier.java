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

import com.google.api.FieldBehavior;
import com.google.api.FieldBehaviorProto;
import com.google.protobuf.Descriptors;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageOrBuilder;
import com.google.protobuf.util.JsonFormat;
import dev.sigstore.proto.bundle.v1.Bundle;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Implements Sigstore Bundle verification. */
public class BundleVerifier {
  static final JsonFormat.Parser JSON_PARSER = JsonFormat.parser();

  /**
   * Parses Sigstore Bundle JSON into protobuf.
   *
   * @param bundleJson input JSON
   * @return a list of required fields missing in a bundle
   * @throws IllegalArgumentException if the JSON is invalid
   */
  public static List<String> allMissingFields(String bundleJson) {
    var bundle = Bundle.newBuilder();
    try {
      JSON_PARSER.merge(bundleJson, bundle);
    } catch (InvalidProtocolBufferException e) {
      throw new IllegalArgumentException("Unable to parse Sigstore Bundle " + bundleJson, e);
    }
    return findMissingFields(bundle);
  }

  static List<String> findMissingFields(MessageOrBuilder message) {
    final List<String> missing = new ArrayList<>();
    findMissingFields(message, "", missing);
    return missing;
  }

  private static void findMissingFields(
      MessageOrBuilder message, String prefix, List<String> missing) {
    // Get missing fields of the message itself
    for (Descriptors.FieldDescriptor field : message.getDescriptorForType().getFields()) {
      if (!isRequired(field)) {
        continue;
      }
      // The parts of a "oneof {...}" are not required on their own
      if (field.getContainingOneof() != null) {
        continue;
      }
      // The field was required, so verify if it contains data
      if (field.isRepeated()) {
        if (message.getRepeatedFieldCount(field) != 0) {
          // Repeated field has values => OK
          continue;
        }
      } else if (message.hasField(field)) {
        // Field is present => OK
        continue;
      }
      // Field is missing
      missing.add(prefix + field.getName());
    }
    // Verify oneof fields. They are required if any of the fields in the oneof is required.
    for (Descriptors.OneofDescriptor oneof : message.getDescriptorForType().getRealOneofs()) {
      if (!message.hasOneof(oneof)
          && oneof.getFields().stream().anyMatch(BundleVerifier::isRequired)) {
        missing.add(prefix + oneof.getName());
      }
    }
    // Recurse into each set message field
    // getAllFields returns only present fields
    for (final Map.Entry<Descriptors.FieldDescriptor, Object> entry :
        message.getAllFields().entrySet()) {
      Descriptors.FieldDescriptor field = entry.getKey();
      Object value = entry.getValue();

      if (field.getJavaType() != Descriptors.FieldDescriptor.JavaType.MESSAGE) {
        continue;
      }
      if (!field.isRepeated()) {
        findMissingFields((MessageOrBuilder) value, subMessagePrefix(prefix, field, -1), missing);
      } else {
        int i = 0;
        //noinspection unchecked
        for (final MessageOrBuilder element : (List<MessageOrBuilder>) value) {
          findMissingFields(element, subMessagePrefix(prefix, field, i++), missing);
        }
      }
    }
  }

  private static String subMessagePrefix(
      String prefix, Descriptors.FieldDescriptor field, int index) {
    StringBuilder result = new StringBuilder(prefix);
    if (field.isExtension()) {
      result.append('(').append(field.getFullName()).append(')');
    } else {
      result.append(field.getName());
    }
    if (index != -1) {
      result.append('[').append(index).append(']');
    }
    result.append('.');
    return result.toString();
  }

  static boolean isRequired(Descriptors.FieldDescriptor field) {
    return field.isRequired()
        || field
            .toProto()
            .getOptions()
            .getExtension(FieldBehaviorProto.fieldBehavior)
            .contains(FieldBehavior.REQUIRED);
  }
}
