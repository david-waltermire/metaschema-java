/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.math;

import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.cst.IExpressionVisitor;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.impl.OperationFunctions;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.LinkedHashMap;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An XPath 3.1
 * <a href="https://www.w3.org/TR/xpath-31/#id-arithmetic">arithmetic
 * expression</a> supporting multiplication.
 * <p>
 * Supports multiplication between:
 * <ul>
 * <li>Numeric values
 * <li>YearMonthDuration × Numeric
 * <li>DayTimeDuration × Numeric
 * </ul>
 *
 * <p>
 * Numeric operands are automatically converted using
 * {@link FunctionUtils#toNumeric}.
 */
public class Multiplication
    extends AbstractBasicArithmeticExpression {
  @NonNull
  private static final Map<Class<? extends IAnyAtomicItem>,
      Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> MULTIPLICATION_STRATEGIES = generateStrategies();

  /**
   * An expression that gets the product result by multiplying two values.
   *
   * @param text
   *          the parsed text of the expression
   * @param left
   *          the item to be divided
   * @param right
   *          the item to divide by
   */
  public Multiplication(
      @NonNull String text,
      @NonNull IExpression left,
      @NonNull IExpression right) {
    super(text, left, right);
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitMultiplication(this, context);
  }

  @Override
  protected Map<
      Class<? extends IAnyAtomicItem>,
      Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> getStrategies() {
    return MULTIPLICATION_STRATEGIES;
  }

  @Override
  protected String unsupportedMessage(String dividend, String divisor) {
    return ObjectUtils.notNull(String.format("Multiplication of '%s' by '%s' is not supported.", dividend, divisor));
  }

  @Override
  protected INumericItem operationAsNumeric(INumericItem dividend, INumericItem divisor) {
    // Default to numeric multiplication
    return OperationFunctions.opNumericMultiply(dividend, divisor);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  @NonNull
  private static Map<
      Class<? extends IAnyAtomicItem>,
      Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> generateStrategies() {
    Map<Class<? extends IAnyAtomicItem>, Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> strategies
        = new LinkedHashMap<>();

    // IYearMonthDurationItem strategies
    Map<Class<? extends IAnyAtomicItem>, OperationStrategy> typeStrategies = new LinkedHashMap<>();
    typeStrategies.put(INumericItem.class,
        (dividend, divisor, dynamicContext) -> OperationFunctions.opMultiplyYearMonthDuration(
            (IYearMonthDurationItem) dividend,
            (INumericItem) divisor));
    strategies.put(IYearMonthDurationItem.class, CollectionUtil.unmodifiableMap(typeStrategies));

    // IDayTimeDurationItem strategies
    typeStrategies = new LinkedHashMap<>();
    typeStrategies.put(INumericItem.class,
        (dividend, divisor, dynamicContext) -> OperationFunctions.opMultiplyDayTimeDuration(
            (IDayTimeDurationItem) dividend,
            (INumericItem) divisor));
    strategies.put(IDayTimeDurationItem.class, CollectionUtil.unmodifiableMap(typeStrategies));

    // INumericItem strategies
    typeStrategies = new LinkedHashMap<>();
    typeStrategies.put(INumericItem.class,
        (dividend, divisor, dynamicContext) -> OperationFunctions.opNumericMultiply(
            (INumericItem) dividend,
            (INumericItem) divisor));
    typeStrategies.put(IYearMonthDurationItem.class,
        (dividend, divisor, dynamicContext) -> OperationFunctions.opMultiplyYearMonthDuration(
            (IYearMonthDurationItem) divisor,
            (INumericItem) dividend));
    typeStrategies.put(IDayTimeDurationItem.class,
        (dividend, divisor, dynamicContext) -> OperationFunctions.opMultiplyDayTimeDuration(
            (IDayTimeDurationItem) divisor,
            (INumericItem) dividend));
    strategies.put(INumericItem.class, CollectionUtil.unmodifiableMap(typeStrategies));

    return CollectionUtil.unmodifiableMap(strategies);
  }

  /**
   * Get the sum of two atomic items.
   *
   * @param leftItem
   *          the first item to multiply
   * @param rightItem
   *          the second item to multiply
   * @return the product of both items
   * @throws InvalidTypeMetapathException
   *           for unsupported operand combinations.
   */
  // TODO: Is this used?
  @SuppressWarnings("PMD.CyclomaticComplexity")
  @NonNull
  public static IAnyAtomicItem multiply(
      @NonNull IAnyAtomicItem leftItem,
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
      INumericItem left = leftItem.toNumeric();
      if (rightItem instanceof INumericItem) {
        INumericItem right = rightItem.toNumeric();
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
          String.format("Multiplication between %s and %s is not supported.",
              leftItem.toSignature(),
              rightItem.toSignature()));
    }
    return retval;
  }
}
