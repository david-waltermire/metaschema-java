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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An XPath 3.1
 * <a href="https://www.w3.org/TR/xpath-31/#id-arithmetic">arithmetic
 * expression</a> supporting modulo.
 * <p>
 * For example: {@code 5 mod 2} evaluates to {@code 1}
 */
public class Modulo
    extends AbstractArithmeticExpression<INumericItem> {

  /**
   * Create an expression that gets the numeric remainder from dividing the
   * dividend by the divisor, also called the "modulo operation".
   *
   * @param text
   *          the parsed text of the expression
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   */
  public Modulo(
      @NonNull String text,
      @NonNull IExpression dividend,
      @NonNull IExpression divisor) {
    super(text, dividend, divisor, INumericItem.class);
  }

  @Override
  public Class<INumericItem> getBaseResultType() {
    return INumericItem.class;
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitModulo(this, context);
  }

  @Override
  protected ISequence<? extends INumericItem> evaluate(DynamicContext dynamicContext, ISequence<?> focus) {
    INumericItem dividend = getLeft().accept(dynamicContext, focus).toNumeric(true);
    INumericItem divisor = getRight().accept(dynamicContext, focus).toNumeric(true);
    return resultOrEmpty(dividend, divisor);
  }

  /**
   * Get the numeric remainder from dividing the dividend by the divisor.
   *
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   * @return the remainder or an empty {@link ISequence} if either item is
   *         {@code null}
   */
  @NonNull
  protected static ISequence<? extends INumericItem> resultOrEmpty(@Nullable INumericItem dividend,
      @Nullable INumericItem divisor) {
    ISequence<? extends INumericItem> retval;
    if (dividend == null || divisor == null) {
      retval = ISequence.empty();
    } else {
      INumericItem result = OperationFunctions.opNumericMod(dividend, divisor);
      retval = ISequence.of(result);
    }
    return retval;
  }
}
