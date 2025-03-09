/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A base class for an assembly instance defined inline.
 *
 * @param <PARENT>
 *          the Java type of the parent model container for this instance
 * @param <DEFINITION>
 *          the Java type of the related assembly definition
 * @param <INSTANCE>
 *          the expected Java type of an instance of this definition
 */
public abstract class AbstractInlineFlagDefinition<
    PARENT extends IModelDefinition,
    DEFINITION extends IFlagDefinition,
    INSTANCE extends IFlagInstance>
    extends AbstractFlagInstance<PARENT, DEFINITION, INSTANCE>
    implements IFlagDefinition,
    IFeatureDefinitionInstanceInlined<DEFINITION, INSTANCE> {

  /**
   * Construct a new inline assembly definition.
   *
   * @param parent
   *          the parent model containing this instance
   */
  protected AbstractInlineFlagDefinition(@NonNull PARENT parent) {
    super(parent);
  }

  @Override
  public final DEFINITION getDefinition() {
    return ObjectUtils.asType(this);
  }

  @Override
  @NonNull
  public final INSTANCE getInlineInstance() {
    return ObjectUtils.asType(this);
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
  public <CONTEXT, RESULT> RESULT accept(@NonNull IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return visitor.visitFlagInstance(this, context);
  }
}
