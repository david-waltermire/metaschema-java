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

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-adjust-dateTime-to-timezone">fn:adjust-dateTime-to-timezone</a>
 * function.
 */
public final class FnAdjustDateTimeToTimezone {
  private static final String NAME = "adjust-dateTime-to-timezone";
  @NonNull
  static final IFunction ONE_ARG_SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IDateTimeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IDateTimeItem.type())
      .returnZeroOrOne()
      .functionHandler(FnAdjustDateTimeToTimezone::executeOneArg)
      .build();
  @NonNull
  static final IFunction TWO_ARG_SIGNATURE = IFunction.builder()
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
      .argument(IArgument.builder()
          .name("timezone")
          .type(IDayTimeDurationItem.type())
          .zeroOrOne()
          .build())
      .returnType(IDateTimeItem.type())
      .returnZeroOrOne()
      .functionHandler(FnAdjustDateTimeToTimezone::executeTwoArg)
      .build();

  private FnAdjustDateTimeToTimezone() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDateTimeItem> executeOneArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDateTimeItem arg = IDateTimeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        // use the implicit timezone
        : ISequence.of(arg.replaceTimezone(dynamicContext.getImplicitTimeZoneAsDayTimeDuration()));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDateTimeItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDateTimeItem arg = IDateTimeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    IDayTimeDurationItem timezone = IDayTimeDurationItem.type().testOrNull(arguments.get(1).getFirstItem(true));
    return arg == null
        // Per spec, return empty sequence if the arg is null
        ? ISequence.empty()
        // use the provided timezone
        : ISequence.of(arg.replaceTimezone(timezone));
  }
}
