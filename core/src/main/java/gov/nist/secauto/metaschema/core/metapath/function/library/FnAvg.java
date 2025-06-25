/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidArgumentFunctionException;
import gov.nist.secauto.metaschema.core.metapath.function.impl.OperationFunctions;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-avg">fn:avg</a>
 * function.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class FnAvg {
  private static final String NAME = "avg";

  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrOne()
      .functionHandler(FnAvg::execute)
      .build();

  private FnAvg() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> sequence = arguments.get(0).ofType(IAnyAtomicItem.type());

    return ISequence.of(average(sequence));
  }

  /**
   * An implementation of XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-avg">fn:avg</a>.
   *
   * @param items
   *          the items to average
   * @return the average
   */
  @SuppressWarnings("PMD.CyclomaticComplexity")
  @Nullable
  public static IAnyAtomicItem average(@NonNull Collection<? extends IAnyAtomicItem> items) {
    if (items.isEmpty()) {
      return null; // NOPMD - readability
    }

    // tell cpd to start ignoring code - CPD-OFF

    Map<Class<? extends IAnyAtomicItem>, Integer> typeCounts = FunctionUtils.countTypes(
        OperationFunctions.aggregateMathTypes(),
        ObjectUtils.notNull(items));

    int count = items.size();
    int dayTimeCount = typeCounts.getOrDefault(IDayTimeDurationItem.class, 0);
    int yearMonthCount = typeCounts.getOrDefault(IYearMonthDurationItem.class, 0);
    int numericCount = typeCounts.getOrDefault(INumericItem.class, 0);

    IAnyAtomicItem retval;
    if (dayTimeCount > 0) {
      if (dayTimeCount != count) {
        throw new InvalidArgumentFunctionException(
            InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
            String.format("Values must all be of type '%s'.", IDayTimeDurationItem.class.getName()));
      }

      List<IDayTimeDurationItem> values = items.stream()
          .map(item -> (IDayTimeDurationItem) item)
          .collect(Collectors.toList());
      retval = averageDayTimeDurations(ObjectUtils.notNull(values));
    } else if (yearMonthCount > 0) {
      if (yearMonthCount != count) {
        throw new InvalidArgumentFunctionException(
            InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
            String.format("Values must all be of type '%s'.", IYearMonthDurationItem.class.getName()));
      }

      List<IYearMonthDurationItem> values = items.stream()
          .map(item -> (IYearMonthDurationItem) item)
          .collect(Collectors.toList());
      retval = averageYearMonthDurations(ObjectUtils.notNull(values));
    } else if (numericCount > 0) {
      if (numericCount != count) {
        throw new InvalidArgumentFunctionException(
            InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
            String.format("Values must all be of type '%s'.", INumericItem.class.getName()));
      }

      List<INumericItem> values = items.stream()
          .map(item -> IDecimalItem.cast(ObjectUtils.notNull(item)))
          .collect(Collectors.toList());
      retval = averageNumeric(ObjectUtils.notNull(values));
    } else {
      throw new InvalidArgumentFunctionException(
          InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
          String.format("Values must all be of type '%s'.",
              OperationFunctions.aggregateMathTypes().stream()
                  .map(Class::getName)
                  .collect(CustomCollectors.joiningWithOxfordComma(","))));
    }

    // resume CPD analysis - CPD-ON

    return retval;
  }

  @NonNull
  private static <T, R extends T> R average(
      @NonNull Collection<? extends T> items,
      @NonNull BinaryOperator<T> adder,
      @NonNull BiFunction<T, IIntegerItem, R> divider) {
    T sum = items.stream()
        .map(item -> (T) item)
        .reduce(adder)
        .get();
    return ObjectUtils.notNull(divider.apply(sum, IIntegerItem.valueOf(items.size())));
  }

  /**
   * Get the average of a collection of day/time duration-based items.
   *
   * @param items
   *          the Metapath items to average
   * @return the average
   */
  @NonNull
  public static IDayTimeDurationItem
      averageDayTimeDurations(@NonNull Collection<? extends IDayTimeDurationItem> items) {
    return average(
        items,
        (BinaryOperator<IDayTimeDurationItem>) OperationFunctions::opAddDayTimeDurations,
        (BiFunction<IDayTimeDurationItem, IIntegerItem,
            IDayTimeDurationItem>) OperationFunctions::opDivideDayTimeDuration);
  }

  /**
   * Get the average of a collection of year/month duration-based items.
   *
   * @param items
   *          the Metapath items to average
   * @return the average
   */
  @NonNull
  public static IYearMonthDurationItem
      averageYearMonthDurations(@NonNull Collection<? extends IYearMonthDurationItem> items) {
    return average(
        items,
        (BinaryOperator<IYearMonthDurationItem>) OperationFunctions::opAddYearMonthDurations,
        (BiFunction<IYearMonthDurationItem, IIntegerItem,
            IYearMonthDurationItem>) OperationFunctions::opDivideYearMonthDuration);
  }

  /**
   * Get the average of a collection of numeric items.
   *
   * @param items
   *          the Metapath items to average
   * @return the average
   */
  @NonNull
  public static IDecimalItem averageNumeric(@NonNull Collection<? extends INumericItem> items) {
    return average(
        items,
        (BinaryOperator<INumericItem>) OperationFunctions::opNumericAdd,
        (BiFunction<INumericItem, IIntegerItem, IDecimalItem>) OperationFunctions::opNumericDivide);
  }
}
