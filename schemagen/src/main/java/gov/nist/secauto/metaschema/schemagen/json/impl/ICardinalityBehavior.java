/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.schemagen.json.impl;

import com.fasterxml.jackson.databind.node.ObjectNode;

import gov.nist.secauto.metaschema.core.model.IModelInstance;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;

import java.util.Collection;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Supports production of a JSON schema property construction for a Metaschema
 * instance that has {@link IModelInstance#getJsonGroupAsBehavior()}.
 * <p>
 * The {@link #behaviorFor(IModelInstanceAbsolute)} method can be used to get
 * the appropriate behavior for a Metaschema definition model instance.
 */
@FunctionalInterface
public interface ICardinalityBehavior {
  /**
   * Used to get the appropriate behavior for a Metaschema definition model
   * instance.
   *
   * @param instance
   *          the Metaschema definition model instance to get the behavior for
   * @return the behavior
   */
  @NonNull
  static ICardinalityBehavior behaviorFor(@NonNull IModelInstanceAbsolute instance) {
    int maxOccurs = instance.getMaxOccurs();

    ICardinalityBehavior retval = null;
    if (maxOccurs == -1 || maxOccurs > 1) {
      // collection
      switch (instance.getJsonGroupAsBehavior()) {
      case KEYED:
        retval = CardinalityBehaviorKeyedObject.instance();
        break;
      case LIST:
        retval = CardinalityBehaviorArray.instance();
        break;
      case SINGLETON_OR_LIST:
        retval = CardinalityBehaviorSingletonOrList.instance();
        break;
      case NONE:
        retval = CardinalityBehaviorSingleton.instance();
        break;
      }
      assert retval != null : String.format("Unsupported group-as in-json binding '%s'.",
          instance.getJsonGroupAsBehavior());
    } else {
      // singleton
      retval = CardinalityBehaviorSingleton.instance();
    }
    return retval;
  }

  /**
   * Generate the JSON schema property construction for this behavior.
   *
   * @param node
   *          the JSON schema node
   * @param instance
   *          the model instance to generate the property construction for
   * @param types
   *          the definition types used to represent property values
   * @param state
   *          the generation state used to generate this JSON schema
   */
  void generate(
      @NonNull ObjectNode node,
      @NonNull IModelInstanceAbsolute instance,
      @NonNull Collection<? extends IJsonSchemaModelDefinition> types,
      @NonNull IJsonGenerationState state);
}
