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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-contains">fn:contains</a>
 * function.
 */
public final class FnContains {
  // CPD-OFF
  @NonNull
  private static final String NAME = "contains";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("arg2")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .returnType(IBooleanItem.type())
      .returnOne()
      .functionHandler(FnContains::execute)
      .build();
  // CPD-ON

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem arg1 = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    IStringItem arg2 = IStringItem.type().ofTypeOrNull(arguments.get(1).getFirstItem(true));

    return ISequence.of(IBooleanItem.valueOf(
        fnContains(
            arg1 == null ? "" : arg1.asString(),
            arg2 == null ? "" : arg2.asString())));
  }

  /**
   * Determine if the string provided in the first argument contains the string in
   * the second argument as a substring.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-contains">fn:contains</a>
   * function.
   *
   * @param arg1
   *          the string to examine
   * @param arg2
   *          the string to check as the leading substring
   * @return {@code true} if {@code arg1} contains {@code arg2}, or {@code false}
   *         otherwise
   */
  public static boolean fnContains(@NonNull String arg1, @NonNull String arg2) {
    boolean retval;
    if (arg2.isEmpty()) {
      retval = true;
    } else if (arg1.isEmpty()) {
      retval = false;
    } else {
      retval = arg1.contains(arg2);
    }
    return retval;
  }

  private FnContains() {
    // disable construction
  }
}
