/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;

import java.util.Locale;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides an base implementation for a set of constraints that target a
 * definition using a target Metapath expression.
 *
 * @param <T>
 *          the Java type of the constraint container
 */
public abstract class AbstractTargetedConstraints<T extends IValueConstrained>
    implements ITargetedConstraints, IFeatureValueConstrained {
  @NonNull
  private final ISource source;
  @NonNull
  private final IMetapathExpression target;
  @NonNull
  private final T constraints;

  /**
   * Construct a new set of targeted constraints.
   *
   * @param source
   *          information about the resource the constraints were sources from
   * @param target
   *          the Metapath expression that can be used to find matching targets
   * @param constraints
   *          the constraints to apply to matching targets
   */
  protected AbstractTargetedConstraints(
      @NonNull ISource source,
      @NonNull IMetapathExpression target,
      @NonNull T constraints) {
    this.source = source;
    this.target = target;
    this.constraints = constraints;
  }

  @Override
  public ISource getSource() {
    return source;
  }

  @Override
  public IMetapathExpression getTarget() {
    return target;
  }

  @Override
  public T getConstraintSupport() {
    return constraints;
  }

  /**
   * Apply the constraints to the provided {@code definition}.
   * <p>
   * This will be called when a definition is found that matches the target
   * expression.
   *
   * @param definition
   *          the definition to apply the constraints to.
   */
  protected void applyTo(@NonNull IValueConstrained definition) {
    getLetExpressions().values().forEach(definition::addLetExpression);
    getAllowedValuesConstraints().forEach(definition::addConstraint);
    getMatchesConstraints().forEach(definition::addConstraint);
    getIndexHasKeyConstraints().forEach(definition::addConstraint);
    getExpectConstraints().forEach(definition::addConstraint);
  }

  @Override
  public void target(IFlagDefinition definition) {
    applyTo(definition);
  }

  @Override
  public void target(IFieldDefinition definition) {
    applyTo(definition);
  }

  @Override
  public void target(IAssemblyDefinition definition) {
    applyTo(definition);
  }

  protected void wrongDefinitionTypeTargeted(@NonNull IDefinition definition) {
    throw new ConstraintInitializationException(
        String.format(
            "The %s named '%s' from metaschema '%s' is incorrectly targeted by a set of" +
                " constraints with the target '%s'. Ensure the target expression is correct in '%s'.",
            definition.getModelType().name().toLowerCase(Locale.ROOT),
            definition.getEffectiveName(),
            definition.getContainingModule().getQName().toString(),
            getTarget(),
            getSource().getLocationHint()));
  }
}
