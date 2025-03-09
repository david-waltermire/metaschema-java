/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A set of constraints targeting a {@link IFlagDefinition} based on a target
 * Metapath expression.
 *
 * @see #getTarget()
 */
public class FlagTargetedConstraints
    extends AbstractTargetedConstraints<IValueConstrained> {

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
  public FlagTargetedConstraints(
      @NonNull ISource source,
      @NonNull IMetapathExpression target,
      @NonNull IValueConstrained constraints) {
    super(source, target, constraints);
  }

  @Override
  public void target(@NonNull IFlagDefinition definition) {
    applyTo(definition);
  }

  @Override
  public void target(@NonNull IFieldDefinition definition) {
    wrongDefinitionTypeTargeted(definition);
  }

  @Override
  public void target(@NonNull IAssemblyDefinition definition) {
    wrongDefinitionTypeTargeted(definition);
  }
}
