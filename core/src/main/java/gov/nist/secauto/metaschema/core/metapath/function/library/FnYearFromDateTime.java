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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-year-from-dateTime">fn:year-from-dateTime</a>.
 * function.
 */
public final class FnYearFromDateTime {
  private static final String NAME = "year-from-dateTime";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IDateTimeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IIntegerItem.type())
      .returnZeroOrOne()
      .functionHandler(FnYearFromDateTime::execute)
      .build();

  private FnYearFromDateTime() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDateTimeItem arg = IDateTimeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        : ISequence.of(fnYearFromDateTime(arg));
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-year-from-dateTime">fn:year-from-dateTime</a>.
   *
   * @param arg
   *          the meta:date-time item from which to extract the year component
   * @return the year component from the date as an integer item
   */
  @NonNull
  public static IIntegerItem fnYearFromDateTime(@NonNull IDateTimeItem arg) {
    return IIntegerItem.valueOf(arg.getYear());
  }
}
