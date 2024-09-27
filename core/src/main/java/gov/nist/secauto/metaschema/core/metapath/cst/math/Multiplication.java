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

public class Multiplication
    extends AbstractBasicArithmeticExpression {

  /**
   * An expression that gets the product result by multiplying two values.
   *
   * @param left
   *          the item to be divided
   * @param right
   *          the item to divide by
   */
  public Multiplication(@NonNull IExpression left, @NonNull IExpression right) {
    super(left, right);
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitMultiplication(this, context);
  }

  /**
   * Get the sum of two atomic items.
   *
   * @param left
   *          the first item to multiply
   * @param right
   *          the second item to multiply
   * @return the product of both items or an empty {@link ISequence} if either
   *         item is {@code null}
   */
  @Override
  @NonNull
  protected IAnyAtomicItem operation(@NonNull IAnyAtomicItem left, @NonNull IAnyAtomicItem right) {
    return multiply(left, right);
  }

  /**
   * Get the sum of two atomic items.
   *
   * @param leftItem
   *          the first item to multiply
   * @param rightItem
   *          the second item to multiply
   * @return the product of both items
   */
  @NonNull
  public static IAnyAtomicItem multiply(@NonNull IAnyAtomicItem leftItem, // NOPMD - intentional
      @NonNull IAnyAtomicItem rightItem) {
    IAnyAtomicItem retval = null;
    if (leftItem instanceof IYearMonthDurationItem) {
      IYearMonthDurationItem left = (IYearMonthDurationItem) leftItem;
      if (rightItem instanceof INumericItem) {
        retval = OperationFunctions.opMultiplyYearMonthDuration(left, (INumericItem) rightItem);
      }
    } else if (leftItem instanceof IDayTimeDurationItem) {
      IDayTimeDurationItem left = (IDayTimeDurationItem) leftItem;
      if (rightItem instanceof INumericItem) {
        retval = OperationFunctions.opMultiplyDayTimeDuration(left, (INumericItem) rightItem);
      }
    } else {
      // handle as numeric
      INumericItem left = FunctionUtils.toNumeric(leftItem);
      if (rightItem instanceof INumericItem) {
        INumericItem right = FunctionUtils.toNumeric(rightItem);
        retval = OperationFunctions.opNumericMultiply(left, right);
      } else if (rightItem instanceof IYearMonthDurationItem) {
        retval = OperationFunctions.opMultiplyYearMonthDuration((IYearMonthDurationItem) rightItem, left);
      } else if (rightItem instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opMultiplyDayTimeDuration((IDayTimeDurationItem) rightItem, left);
      }
    }
    if (retval == null) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("The expression '%s * %s' is not supported", leftItem.getClass().getName(),
              rightItem.getClass().getName()));
    }
    return retval;
  }
}
