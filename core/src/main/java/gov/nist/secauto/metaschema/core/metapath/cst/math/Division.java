/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.math;

import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.cst.IExpression;
import gov.nist.secauto.metaschema.core.metapath.cst.IExpressionVisitor;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.OperationFunctions;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;

public class Division
    extends AbstractBasicArithmeticExpression {

  /**
   * An expression that gets the quotient result by dividing the dividend by the
   * divisor.
   *
   * @param dividend
   *          the expression whose result is to be divided
   * @param divisor
   *          the expression whose result is to divide by
   */
  public Division(@NonNull IExpression dividend, @NonNull IExpression divisor) {
    super(dividend, divisor);
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitDivision(this, context);
  }

  /**
   * Get the quotient result by dividing the dividend by the divisor.
   *
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   * @return the quotient result or an empty {@link ISequence} if either item is
   *         {@code null}
   */
  @Override
  @NonNull
  protected IAnyAtomicItem operation(@NonNull IAnyAtomicItem dividend, @NonNull IAnyAtomicItem divisor) {
    return divide(dividend, divisor);
  }

  /**
   * Get the quotient result by dividing the dividend by the divisor.
   *
   * @param dividend
   *          the item to be divided
   * @param divisor
   *          the item to divide by
   * @return the quotient result
   */
  @NonNull
  public static IAnyAtomicItem divide(@NonNull IAnyAtomicItem dividend, // NOPMD - intentional
      @NonNull IAnyAtomicItem divisor) {
    IAnyAtomicItem retval = null;
    if (dividend instanceof IYearMonthDurationItem) {
      IYearMonthDurationItem left = (IYearMonthDurationItem) dividend;
      if (divisor instanceof INumericItem) {
        retval = OperationFunctions.opDivideYearMonthDuration(left, (INumericItem) divisor);
      } else if (divisor instanceof IYearMonthDurationItem) {
        // TODO: find a way to support this
        throw new UnsupportedOperationException();
      }
    } else if (dividend instanceof IDayTimeDurationItem) {
      IDayTimeDurationItem left = (IDayTimeDurationItem) dividend;
      if (divisor instanceof INumericItem) {
        retval = OperationFunctions.opDivideDayTimeDuration(left, (INumericItem) divisor);
      } else if (divisor instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opDivideDayTimeDurationByDayTimeDuration(left, (IDayTimeDurationItem) divisor);
      }
    } else {
      // handle as numeric
      INumericItem left = FunctionUtils.toNumeric(dividend);
      if (divisor instanceof INumericItem) {
        INumericItem right = FunctionUtils.toNumeric(divisor);
        retval = OperationFunctions.opNumericDivide(left, right);
      } else if (divisor instanceof IYearMonthDurationItem) {
        retval = OperationFunctions.opMultiplyYearMonthDuration((IYearMonthDurationItem) divisor, left);
      } else if (divisor instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opMultiplyDayTimeDuration((IDayTimeDurationItem) divisor, left);
      }
    }
    if (retval == null) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("The expression '%s / %s' is not supported", dividend.getClass().getName(),
              divisor.getClass().getName()));
    }
    return retval;
  }
}
