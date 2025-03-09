/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import java.util.Locale;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A marker interface for a choice of allowed instances in a Metachema.
 */
public interface IChoiceInstance extends IModelInstanceAbsolute, IContainerModelAbsolute {

  /**
   * Provides the Metaschema model type of "CHOICE".
   *
   * @return the model type
   */
  @Override
  default ModelType getModelType() {
    return ModelType.CHOICE;
  }

  @Override
  default IAssemblyDefinition getOwningDefinition() {
    return getParentContainer().getOwningDefinition();
  }

  @Override
  default int getMinOccurs() {
    return 1;
  }

  @Override
  default int getMaxOccurs() {
    return 1;
  }

  @Override
  default IEnhancedQName getEffectiveXmlGroupAsQName() {
    // never grouped
    return null;
  }

  @Override
  default boolean isEffectiveValueWrappedInXml() {
    throw new UnsupportedOperationException("not applicable");
  }

  @SuppressWarnings("null")
  @Override
  default String toCoordinates() {
    return String.format("%s-instance:%s:%s@%d",
        getModelType().toString().toLowerCase(Locale.ROOT),
        getContainingDefinition().getContainingModule().getShortName(),
        getContainingDefinition().getName(),
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
    return visitor.visitChoiceInstance(this, context);
  }
}
