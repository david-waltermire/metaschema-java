/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.math;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An immutable binary expression that supports basic arithmetic evaluation.
 * <p>
 * The result type is determined through static analysis of the sub-expressions,
 * which may result in a more specific type that is a sub-class of the base
 * result type.
 * <p>
 * The arithmetic operation method
 * {@link #operation(IAnyAtomicItem, IAnyAtomicItem, DynamicContext)} must be
 * implemented by extending classes to provide the evaluation logic.
 */
public abstract class AbstractBasicArithmeticExpression
    extends AbstractArithmeticExpression<IAnyAtomicItem> {

  /**
   * An expression that represents a basic arithmetic operation on two values.
   *
   * @param text
   *          the parsed text of the expression
   * @param left
   *          the first item
   * @param right
   *          the second item
   */
  public AbstractBasicArithmeticExpression(
      @NonNull String text,
      @NonNull IExpression left,
      @NonNull IExpression right) {
    super(text, left, right, IAnyAtomicItem.class);
  }

  @Override
  public Class<IAnyAtomicItem> getBaseResultType() {
    return IAnyAtomicItem.class;
  }

  @Override
  protected ISequence<? extends IAnyAtomicItem> evaluate(DynamicContext dynamicContext, ISequence<?> focus) {
    IAnyAtomicItem leftItem = ISequence.of(getLeft().accept(dynamicContext, focus).atomize()).getFirstItem(true);
    IAnyAtomicItem rightItem = ISequence.of(getRight().accept(dynamicContext, focus).atomize()).getFirstItem(true);

    return resultOrEmpty(leftItem, rightItem, dynamicContext);
  }

  /**
   * Setup the operation on two atomic items.
   *
   * @param leftItem
   *          the first item
   * @param rightItem
   *          the second item
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return the result of the operation or an empty {@link ISequence} if either
   *         item is {@code null}
   */
  @NonNull
  protected ISequence<? extends IAnyAtomicItem> resultOrEmpty(
      @Nullable IAnyAtomicItem leftItem,
      @Nullable IAnyAtomicItem rightItem,
      @NonNull DynamicContext dynamicContext) {
    ISequence<? extends IAnyAtomicItem> retval;
    if (leftItem == null || rightItem == null) {
      retval = ISequence.empty();
    } else {
      IAnyAtomicItem result = operation(leftItem, rightItem, dynamicContext);
      retval = ISequence.of(result);
    }
    return retval;
  }

  /**
   * Performs the arithmetic operation using the two provided values.
   *
   * @param left
   *          the first item
   * @param right
   *          the second item
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return the result of the operation
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  protected IAnyAtomicItem operation(
      @NonNull IAnyAtomicItem left,
      @NonNull IAnyAtomicItem right,
      @NonNull DynamicContext dynamicContext) {

    Map<
        Class<? extends IAnyAtomicItem>,
        Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> strategies = getStrategies();
    Class<? extends IAnyAtomicItem> leftClass = left.getClass();

    // Find matching strategy for minuend type
    Map<Class<? extends IAnyAtomicItem>, OperationStrategy> typeStrategies = null;
    // CHECKSTYLE.OFF: Indentation
    for (Map.Entry<
        Class<? extends IAnyAtomicItem>,
        Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> entry : strategies.entrySet()) {
      if (entry.getKey().isAssignableFrom(leftClass)) {
        // this is a matching strategy map
        typeStrategies = entry.getValue();
        break;
      }
    }
    // CHECKSTYLE.ON: Indentation

    if (typeStrategies == null) {
      return operationAsNumeric(left.toNumeric(), right.toNumeric());
    }

    // Find matching strategy for subtrahend type
    Class<? extends IAnyAtomicItem> rightClass = right.getClass();
    for (Map.Entry<Class<? extends IAnyAtomicItem>, OperationStrategy> entry : typeStrategies.entrySet()) {
      if (entry.getKey().isAssignableFrom(rightClass)) {
        // this is matching strategy, execute it
        return entry.getValue().execute(left, right, dynamicContext);
      }
    }

    throw new UnsupportedOperationException(unsupportedMessage(
        left.toSignature(),
        right.toSignature()));
  }

  /**
   * Provides a mapping of the left class to a mapping of the right class and the
   * strategy to use to compute the operation.
   * <p>
   * This mapping is used to lookup the strategy to use based on the left and
   * right classes.
   *
   * @return the mapping
   */
  @NonNull
  protected abstract Map<
      Class<? extends IAnyAtomicItem>,
      Map<Class<? extends IAnyAtomicItem>, OperationStrategy>> getStrategies();

  /**
   * Generates an error message for unsupported operand types.
   *
   * @param left
   *          the string representation of the left operand type
   * @param right
   *          the string representation of the right operand type
   * @return the formatted error message
   */
  @NonNull
  protected abstract String unsupportedMessage(@NonNull String left, @NonNull String right);

  /**
   * Performs the arithmetic operation on numeric items.
   *
   * @param left
   *          the first numeric item
   * @param right
   *          the second numeric item
   * @return the result of the numeric operation
   */
  @NonNull
  protected abstract INumericItem operationAsNumeric(@NonNull INumericItem left, @NonNull INumericItem right);

  /**
   * Provides a callback for resolving arithmetic operations.
   */
  @FunctionalInterface
  protected interface OperationStrategy {
    /**
     * Called to execute an arithmetic operation.
     *
     * @param left
     *          the left side of the arithmetic operation
     * @param right
     *          the right side of the arithmetic operation
     * @param dynamicContext
     *          the evaluation dynamic context
     * @return the arithmetic result
     */
    @NonNull
    IAnyAtomicItem execute(
        @NonNull IAnyAtomicItem left,
        @NonNull IAnyAtomicItem right,
        @NonNull DynamicContext dynamicContext);
  }
}
