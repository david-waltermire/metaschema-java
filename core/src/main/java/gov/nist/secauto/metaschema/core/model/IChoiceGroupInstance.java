/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;

import java.util.Locale;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An Metaschema model instance representing a grouped set of objects consisting
 * of heterogeneous object types.
 */
public interface IChoiceGroupInstance
    extends IModelInstanceAbsolute, IContainerModelGrouped {

  /**
   * The default max-occurs value for a choice group. {@code -1} represents an
   * unbounded occurance.
   */
  int DEFAULT_CHOICE_GROUP_GROUP_AS_MAX_OCCURS = -1;

  /**
   * The default JSON property value used to identify the specific type of the
   * object.
   */
  @NonNull
  String DEFAULT_JSON_DISCRIMINATOR_PROPERTY_NAME = "object-type";

  /**
   * {@inheritDoc}
   *
   * @see #DEFAULT_CHOICE_GROUP_GROUP_AS_MAX_OCCURS
   */
  @Override
  default int getMaxOccurs() {
    return DEFAULT_CHOICE_GROUP_GROUP_AS_MAX_OCCURS;
  }

  /**
   * Provides the Metaschema model type of "CHOICE".
   *
   * @return the model type
   */
  @Override
  default ModelType getModelType() {
    return ModelType.CHOICE_GROUP;
  }

  /**
   * Get the JSON property to use to discriminate between JSON objects.
   *
   * @return the discriminator property
   * @see #DEFAULT_JSON_DISCRIMINATOR_PROPERTY_NAME
   */
  @NonNull
  String getJsonDiscriminatorProperty();

  @Override
  default boolean isEffectiveValueWrappedInXml() {
    return true;
  }

  /**
   * Get the effective name of the JSON key flag, if a JSON key is configured.
   * <p>
   * This name is expected to be in the same namespace as the containing model
   * element (i.e. choice group, assembly, field).
   *
   * @return the name of the JSON key flag if configured, or {@code null}
   *         otherwise
   */
  @Nullable
  String getJsonKeyFlagInstanceName();

  /**
   * Get the named model instance for the provided choice group item.
   *
   * @param item
   *          the item to get the instance for
   * @return the named model instance for the provided choice group item
   */
  @NonNull
  default INamedModelInstanceGrouped getItemInstance(@NonNull Object item) {
    throw new UnsupportedOperationException("Method not needed.");
  }

  @Override
  default MarkupMultiline getRemarks() {
    // no remarks
    return null;
  }

  @SuppressWarnings("null")
  @Override
  default String toCoordinates() {
    return String.format("%s-instance:%s:%s/%s@%d",
        getModelType().toString().toLowerCase(Locale.ROOT),
        getContainingDefinition().getContainingModule().getShortName(),
        getContainingDefinition().getName(),
        getGroupAsName(),
        hashCode());
  }

  /**
   * A visitor callback.
   *
   * @param <CONTEXT>
   *          the type of the context parameter
   * @param <RESULT>
   *          the type of the visitor result
   * @param visitor
   *          the calling visitor
   * @param context
   *          a parameter used to pass contextual information between visitors
   * @return the visitor result
   */
  @Override
  default <CONTEXT, RESULT> RESULT accept(@NonNull IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return visitor.visitChoiceGroupInstance(this, context);
  }
}
