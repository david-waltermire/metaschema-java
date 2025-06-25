/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.datatype.adapter.DecimalAdapter;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.ITimeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-time">fn:seconds-from-time</a>.
 * function.
 */
public final class FnSecondsFromTime {
  private static final String NAME = "seconds-from-time";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(ITimeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IDecimalItem.type())
      .returnZeroOrOne()
      .functionHandler(FnSecondsFromTime::execute)
      .build();

  private FnSecondsFromTime() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDecimalItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ITimeItem arg = ITimeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        : ISequence.of(fnSecondsFromTime(arg));
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-time">fn:seconds-from-time</a>.
   *
   * @param arg
   *          the meta:time item from which to extract the second component
   * @return the second component from the date as a decimal item
   */
  @NonNull
  public static IDecimalItem fnSecondsFromTime(@NonNull ITimeItem arg) {
    Duration duration = Duration.ofSeconds(arg.getSecond(), arg.getNano());
    return IDecimalItem.valueOf(ObjectUtils.notNull(
        BigDecimal.valueOf(duration.getSeconds())
            .add(BigDecimal.valueOf(duration.getNano())
                .divide(BigDecimal.valueOf(1_000_000_000.0), DecimalAdapter.mathContext()))));
  }
}
