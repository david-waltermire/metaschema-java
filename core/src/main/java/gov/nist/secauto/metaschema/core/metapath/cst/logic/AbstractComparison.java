/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.logic;

import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.cst.AbstractBinaryExpression;
import gov.nist.secauto.metaschema.core.metapath.function.ComparisonFunctions;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A common base class for all comparison nodes, which consist of two
 * expressions representing the left and right sides of the comparison, and a
 * comparison operator.
 */
public abstract class AbstractComparison
    extends AbstractBinaryExpression<IExpression, IExpression>
    implements IBooleanLogicExpression {

  @NonNull
  private final ComparisonFunctions.Operator operator;

  /**
   * Construct an expression that compares the result of the {@code right}
   * expression with the result of the {@code left} expression using the specified
   * {@code operator}.
   *
   * @param text
   *          the parsed text of the expression
   * @param left
   *          the expression to compare against
   * @param operator
   *          the comparison operator
   * @param right
   *          the expression to compare with
   */
  public AbstractComparison(
      @NonNull String text,
      @NonNull IExpression left,
      @NonNull ComparisonFunctions.Operator operator,
      @NonNull IExpression right) {
    super(text, left, right);
    this.operator = ObjectUtils.requireNonNull(operator, "operator");
  }

  /**
   * Get the comparison operator.
   *
   * @return the operator
   */
  @NonNull
  public ComparisonFunctions.Operator getOperator() {
    return operator;
  }

  @SuppressWarnings("null")
  @Override
  public String toCSTString() {
    return String.format("%s[operator=%s]", getClass().getName(), operator);
  }

}
