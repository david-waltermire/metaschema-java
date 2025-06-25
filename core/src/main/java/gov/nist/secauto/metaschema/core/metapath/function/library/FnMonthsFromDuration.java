/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-months-from-duration">fn:months-from-duration</a>.
 * function.
 */
public final class FnMonthsFromDuration {
  private static final String NAME = "months-from-duration";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IDurationItem.type())
          .zeroOrOne()
          .build())
      .returnType(IIntegerItem.type())
      .returnZeroOrOne()
      .functionHandler(FnMonthsFromDuration::execute)
      .build();

  private FnMonthsFromDuration() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDurationItem arg = IDurationItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        : arg instanceof IDayTimeDurationItem
            // day-time durations do not have months granularity
            ? ISequence.of(IIntegerItem.ZERO)
            // get the hours
            : ISequence.of(fnMonthsFromDuration((IYearMonthDurationItem) arg));
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-months-from-duration">fn:months-from-duration</a>.
   *
   * @param arg
   *          the meta:duration item from which to extract the months component
   * @return the months component from the duration as an integer item
   */
  @NonNull
  public static IIntegerItem fnMonthsFromDuration(@NonNull IYearMonthDurationItem arg) {
    long months = arg.asTotalMonths();
    return IIntegerItem.valueOf(months % 12);
  }
}
