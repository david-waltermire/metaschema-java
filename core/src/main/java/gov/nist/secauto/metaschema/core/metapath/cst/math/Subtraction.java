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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;

public class Subtraction
    extends AbstractBasicArithmeticExpression {

  /**
   * An expression that gets the difference of two atomic data items.
   *
   * @param minuend
   *          an expression whose result is the value being subtracted from
   * @param subtrahend
   *          an expression whose result is the value being subtracted
   */
  public Subtraction(@NonNull IExpression minuend, @NonNull IExpression subtrahend) {
    super(minuend, subtrahend);
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitSubtraction(this, context);
  }

  /**
   * Get the difference of two atomic items.
   *
   * @param minuend
   *          the item being subtracted from
   * @param subtrahend
   *          the item being subtracted
   * @return the difference of the items or an empty {@link ISequence} if either
   *         item is {@code null}
   */
  @Override
  @NonNull
  protected IAnyAtomicItem operation(@NonNull IAnyAtomicItem minuend, @NonNull IAnyAtomicItem subtrahend) {
    return subtract(minuend, subtrahend);
  }

  /**
   * Get the difference of two atomic items.
   *
   * @param minuend
   *          the item being subtracted from
   * @param subtrahend
   *          the item being subtracted
   * @return the difference of the items
   */
  @NonNull
  public static IAnyAtomicItem subtract(@NonNull IAnyAtomicItem minuend, // NOPMD - intentional
      @NonNull IAnyAtomicItem subtrahend) {

    IAnyAtomicItem retval = null;
    if (minuend instanceof IDateItem) {
      IDateItem left = (IDateItem) minuend;

      if (subtrahend instanceof IDateItem) {
        retval = OperationFunctions.opSubtractDates(left, (IDateItem) subtrahend);
      } else if (subtrahend instanceof IYearMonthDurationItem) {
        retval = OperationFunctions.opSubtractYearMonthDurationFromDate(left, (IYearMonthDurationItem) subtrahend);
      } else if (subtrahend instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opSubtractDayTimeDurationFromDate(left, (IDayTimeDurationItem) subtrahend);
      }
    } else if (minuend instanceof IDateTimeItem) {
      IDateTimeItem left = (IDateTimeItem) minuend;
      if (subtrahend instanceof IDateTimeItem) {
        retval = OperationFunctions.opSubtractDateTimes(left, (IDateTimeItem) subtrahend);
      } else if (subtrahend instanceof IYearMonthDurationItem) {
        retval = OperationFunctions.opSubtractYearMonthDurationFromDateTime(left, (IYearMonthDurationItem) subtrahend);
      } else if (subtrahend instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opSubtractDayTimeDurationFromDateTime(left, (IDayTimeDurationItem) subtrahend);
      }
    } else if (minuend instanceof IYearMonthDurationItem) {
      IYearMonthDurationItem left = (IYearMonthDurationItem) minuend;
      if (subtrahend instanceof IYearMonthDurationItem) {
        retval = OperationFunctions.opSubtractYearMonthDurations(left, (IYearMonthDurationItem) subtrahend);
      }
    } else if (minuend instanceof IDayTimeDurationItem) {
      IDayTimeDurationItem left = (IDayTimeDurationItem) minuend;
      if (subtrahend instanceof IDayTimeDurationItem) {
        retval = OperationFunctions.opSubtractDayTimeDurations(left, (IDayTimeDurationItem) subtrahend);
      }
    } else {
      // handle as numeric
      INumericItem left = FunctionUtils.toNumeric(minuend);
      INumericItem right = FunctionUtils.toNumeric(subtrahend);
      retval = OperationFunctions.opNumericSubtract(left, right);
    }
    if (retval == null) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("The expression '%s - %s' is not supported", minuend.getClass().getName(),
              subtrahend.getClass().getName()));
    }
    return retval;
  }
}
