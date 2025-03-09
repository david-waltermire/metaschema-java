/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ModelTargetedConstraints
    extends AbstractTargetedConstraints<IModelConstrained>
    implements IFeatureModelConstrained {

  public ModelTargetedConstraints(
      @NonNull ISource source,
      @NonNull IMetapathExpression target,
      @NonNull IModelConstrained constraints) {
    super(source, target, constraints);
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
  protected void applyTo(@NonNull IModelConstrained definition) {
    applyTo((IValueConstrained) definition);
    getIndexConstraints().forEach(definition::addConstraint);
    getUniqueConstraints().forEach(definition::addConstraint);
    getHasCardinalityConstraints().forEach(definition::addConstraint);
  }

  @Override
  public void target(IAssemblyDefinition definition) {
    applyTo(definition);
  }
}
