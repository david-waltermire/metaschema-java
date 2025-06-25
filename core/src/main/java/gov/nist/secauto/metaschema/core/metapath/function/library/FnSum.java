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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-sum">fn:sum</a>
 * functions.
 */
public final class FnSum {
  private static final String NAME = "sum";

  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
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
      .returnOne()
      .functionHandler(FnSum::executeOneArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
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
      .argument(IArgument.builder()
          .name("zero")
          .type(IAnyAtomicItem.type())
          .zeroOrOne()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrOne()
      .functionHandler(FnSum::executeTwoArg)
      .build();

  private FnSum() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeOneArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> sequence = arguments.get(0).ofType(IAnyAtomicItem.type());
    return ISequence.of(sum(sequence, IIntegerItem.ZERO));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> sequence = arguments.get(0).ofType(IAnyAtomicItem.type());
    IAnyAtomicItem zero = IAnyAtomicItem.type().ofTypeOrNull(arguments.get(1).getFirstItem(true));
    return ISequence.of(sum(sequence, zero));
  }

  /**
   * An implementation of XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-sum">fn:sum</a>.
   *
   * @param items
   *          the items to sum
   * @param zero
   *          the value to use if no items are provided, which can be {@code null}
   * @return the average
   */
  @SuppressWarnings({
      "PMD.OnlyOneReturn", // readability
      "PMD.CyclomaticComplexity" // ok
  })
  @Nullable
  public static IAnyAtomicItem sum(
      @NonNull List<? extends IAnyAtomicItem> items,
      @Nullable IAnyAtomicItem zero) {
    if (items.isEmpty()) {
      return zero;
    }

    if (items.size() == 1) {
      return items.get(0);
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

      retval = items.stream()
          .map(item -> (IDayTimeDurationItem) item)
          .reduce((item1, item2) -> OperationFunctions.opAddDayTimeDurations(
              ObjectUtils.notNull(item1),
              ObjectUtils.notNull(item2)))
          .get();
    } else if (yearMonthCount > 0) {
      if (yearMonthCount != count) {
        throw new InvalidArgumentFunctionException(
            InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
            String.format("Values must all be of type '%s'.", IYearMonthDurationItem.class.getName()));
      }

      retval = items.stream()
          .map(item -> (IYearMonthDurationItem) item)
          .reduce((item1, item2) -> OperationFunctions.opAddYearMonthDurations(
              ObjectUtils.notNull(item1),
              ObjectUtils.notNull(item2)))
          .get();
    } else if (numericCount > 0) {
      if (numericCount != count) {
        throw new InvalidArgumentFunctionException(
            InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
            String.format("Values must all be of type '%s'.", INumericItem.class.getName()));
      }

      retval = items.stream()
          .map(item -> (INumericItem) item)
          .reduce((item1, item2) -> OperationFunctions.opNumericAdd(
              ObjectUtils.notNull(item1),
              ObjectUtils.notNull(item2)))
          .get();
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
}
