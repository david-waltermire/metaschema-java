/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.schemagen.json.impl;

import com.fasterxml.jackson.databind.node.ObjectNode;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a JSON schema for a given Metaschema-based model object, which may
 * be part of a larger JSON schema.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IJsonSchema {

  /**
   * Generate an inline JSON schema.
   *
   * @param node
   *          the property JSON object
   * @param state
   *          the schema generation state used for context
   */
  void generateInlineJsonSchema(@NonNull ObjectNode node, @NonNull IJsonGenerationState state);

  /**
   * Generate a JSON schema or a reference to a JSON schema definition.
   * <p>
   * This method will determine if this schema is intended to be inline or used as
   * a JSON schema definition by reference.
   *
   * @param node
   *          the property JSON object
   * @param state
   *          the schema generation state used for context
   */
  default void generateJsonSchemaOrDefinitionRef(@NonNull ObjectNode node, @NonNull IJsonGenerationState state) {
    generateInlineJsonSchema(node, state);
  }

  /**
   * Determine if the schema is defined inline or as a global definition.
   *
   * @param state
   *          the schema generation state used for context
   * @return {@code true} if the schema is to be defined inline or {@code false}
   *         if the schema is to be defined globally
   */
  default boolean isInline(@NonNull IJsonGenerationState state) {
    return true;
  }
}
