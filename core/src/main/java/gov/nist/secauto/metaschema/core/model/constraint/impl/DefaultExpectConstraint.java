/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IExpectConstraint;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Represents an expect constraint.
 * <p>
 * Requires that the associated test evaluates to {@link IBooleanItem#TRUE}
 * against the target.
 */
public final class DefaultExpectConstraint
    extends AbstractConfigurableMessageConstraint
    implements IExpectConstraint {
  @NonNull
  private final IMetapathExpression test;

  /**
   * Construct a new expect constraint.
   *
   * @param id
   *          the optional identifier for the constraint
   * @param formalName
   *          the constraint's formal name or {@code null} if not provided
   * @param description
   *          the constraint's semantic description or {@code null} if not
   *          provided
   * @param source
   *          information about the constraint source
   * @param level
   *          the significance of a violation of this constraint
   * @param target
   *          the Metapath expression identifying the nodes the constraint targets
   * @param properties
   *          a collection of associated properties
   * @param test
   *          a Metapath expression that is evaluated against the target node to
   *          determine if the constraint passes
   * @param message
   *          an optional message to emit when the constraint is violated
   * @param remarks
   *          optional remarks describing the intent of the constraint
   */
  public DefaultExpectConstraint(
      @Nullable String id,
      @Nullable String formalName,
      @Nullable MarkupLine description,
      @NonNull ISource source,
      @NonNull Level level,
      @NonNull IMetapathExpression target,
      @NonNull Map<IAttributable.Key, Set<String>> properties,
      @NonNull IMetapathExpression test,
      @Nullable String message,
      @Nullable MarkupMultiline remarks) {
    super(id, formalName, description, source, level, target, properties, message, remarks);
    this.test = test;
  }

  @Override
  public IMetapathExpression getTest() {
    return test;
  }
}
