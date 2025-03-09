/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IFieldInstanceAbsolute extends IFieldInstance, INamedModelInstanceAbsolute {

  @Override
  default boolean isEffectiveValueWrappedInXml() {
    return isInXmlWrapped() || !getDefinition().getJavaTypeAdapter().isUnrappedValueAllowedInXml();
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
    return visitor.visitFieldInstance(this, context);
  }
}
