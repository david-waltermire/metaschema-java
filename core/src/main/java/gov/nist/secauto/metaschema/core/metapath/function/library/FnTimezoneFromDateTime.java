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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-dateTime">fn:timezone-from-dateTime</a>
 * function.
 */
public final class FnTimezoneFromDateTime {
  private static final String NAME = "timezone-from-dateTime";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .zeroOrOne()
          .type(IDateTimeItem.type())
          .build())
      .returnType(IDayTimeDurationItem.type())
      .returnZeroOrOne()
      .functionHandler(FnTimezoneFromDateTime::execute)
      .build();

  private FnTimezoneFromDateTime() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDayTimeDurationItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDateTimeItem arg
        = IDateTimeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        : ISequence.of(fnTimezoneFromDateTime(arg));
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-dateTime">fn:timezone-from-dateTime</a>.
   *
   * @param arg
   *          the meta:date-time item from which to extract the timezone component
   * @return the timezone component from the date/time or {@code null} if no
   *         timezone is present
   */
  @Nullable
  public static IDayTimeDurationItem fnTimezoneFromDateTime(@NonNull IDateTimeItem arg) {
    return arg.getOffset();
  }

}
