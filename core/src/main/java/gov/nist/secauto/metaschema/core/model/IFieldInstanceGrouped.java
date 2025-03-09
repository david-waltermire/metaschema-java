/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IFieldInstanceGrouped extends INamedModelInstanceGrouped, IFieldInstance {

  /**
   * Determines if the field is configured to have a wrapper in XML.
   *
   * @return {@code true} if an XML wrapper is required, or {@code false}
   *         otherwise
   */
  @Override
  default boolean isInXmlWrapped() {
    // must always be wrapped
    return true;
  }

  @Override
  default boolean isEffectiveValueWrappedInXml() {
    // must always be wrapped
    return true;
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
