/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.math;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.cst.IExpressionVisitor;
import gov.nist.secauto.metaschema.core.metapath.function.impl.OperationFunctions;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An XPath 3.1
 * <a href="https://www.w3.org/TR/xpath-31/#id-arithmetic">arithmetic
 * expression</a> supporting integer division.
 */
public class IntegerDivision
    extends AbstractArithmeticExpression<IIntegerItem> {

  /**
   * Create an expression that gets the whole number quotient result by dividing
   * the dividend by the divisor.
   *
   * @param text
   *          the parsed text of the expression
   * @param dividend
   *          the expression whose item result will be divided
   * @param divisor
   *          the expression whose item result will be divided by
   */
  public IntegerDivision(
      @NonNull String text,
      @NonNull IExpression dividend,
      @NonNull IExpression divisor) {
    super(text, dividend, divisor, IIntegerItem.class);
  }

  @Override
  public Class<IIntegerItem> getBaseResultType() {
    return IIntegerItem.class;
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitIntegerDivision(this, context);
  }

  @Override
  protected ISequence<? extends IIntegerItem> evaluate(DynamicContext dynamicContext, ISequence<?> focus) {
    INumericItem dividend = ISequence.of(getLeft().accept(dynamicContext, focus).atomize()).toNumeric(true);
    INumericItem divisor = ISequence.of(getRight().accept(dynamicContext, focus).atomize()).toNumeric(true);
    return resultOrEmpty(dividend, divisor);
  }

  /**
   * Get the whole number quotient result by dividing the dividend by the divisor.
   *
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   * @return the quotient result or an empty {@link ISequence} if either item is
   *         {@code null}
   */
  @NonNull
  protected static ISequence<? extends IIntegerItem> resultOrEmpty(@Nullable INumericItem dividend,
      @Nullable INumericItem divisor) {
    ISequence<? extends IIntegerItem> retval;
    if (dividend == null || divisor == null) {
      retval = ISequence.empty();
    } else {
      IIntegerItem result = divide(dividend, divisor);
      retval = ISequence.of(result);
    }
    return retval;
  }

  /**
   * Get the whole number quotient result by dividing the dividend by the divisor.
   *
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   * @return the quotient result
   */
  public static IIntegerItem divide(@NonNull INumericItem dividend, @NonNull INumericItem divisor) {
    return OperationFunctions.opNumericIntegerDivide(dividend, divisor);
  }
}
