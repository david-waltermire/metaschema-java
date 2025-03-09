/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IFlagInstance extends IFlag, IValuedInstance, IInstanceAbsolute {

  boolean DEFAULT_FLAG_REQUIRED = false;

  @Override
  IModelDefinition getParentContainer();

  @Override
  IFlagDefinition getDefinition();

  @Override
  default IModelDefinition getContainingDefinition() {
    return getParentContainer();
  }

  /**
   * Determines if a flag value is required to be provided.
   *
   * @return {@code true} if a value is required, or {@code false} otherwise
   * @see #DEFAULT_FLAG_REQUIRED
   */
  default boolean isRequired() {
    return DEFAULT_FLAG_REQUIRED;
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
    return visitor.visitFlagInstance(this, context);
  }
}
