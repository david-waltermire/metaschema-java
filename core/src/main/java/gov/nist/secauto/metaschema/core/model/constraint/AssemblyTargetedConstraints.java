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

import java.util.List;
import java.util.function.Supplier;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A set of constraints targeting a {@link IAssemblyDefinition} based on a
 * target Metapath expression.
 */
public class AssemblyTargetedConstraints
    extends ModelTargetedConstraints {

  /**
   * Construct a new set of targeted constraints.
   *
   * @param source
   *          information about the resource the constraints were sources from
   * @param targets
   *          a supplier to get the Metapath expressions that can be used to find
   *          matching targets
   * @param constraints
   *          the constraints to apply to matching targets
   */
  public AssemblyTargetedConstraints(
      @NonNull ISource source,
      @NonNull Supplier<List<IMetapathExpression>> targets,
      @NonNull IModelConstrained constraints) {
    super(source, targets, constraints);
  }

  @Override
  public void target(@NonNull IFlagDefinition definition) {
    wrongDefinitionTypeTargeted(definition);
  }

  @Override
  public void target(@NonNull IFieldDefinition definition) {
    wrongDefinitionTypeTargeted(definition);
  }

  @Override
  public void target(@NonNull IAssemblyDefinition definition) {
    applyTo(definition);
  }
}
