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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.StringUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

// CPD-OFF
/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-substring-before">fn:substring-before</a>
 * function.
 */
public final class FnSubstringBefore {
  private static final String NAME = "substring-before";
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
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
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnSubstringBefore::executeTwoArg)
      .build();
  // CPD-ON

  private FnSubstringBefore() {
    // disable construction
  }

  @SuppressWarnings({ "unused" })
  @NonNull
  private static ISequence<IStringItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    // From the XPath 3.1 specification:
    // If the value of $arg1 or $arg2 is the empty sequence, or contains only
    // ignorable collation units, it is interpreted as the zero-length string.
    IStringItem arg1 = arguments.get(0).isEmpty()
        ? IStringItem.valueOf("")
        : IStringItem.type().ofType(arguments.get(0).getFirstItem(true));
    IStringItem arg2 = arguments.get(1).isEmpty()
        ? IStringItem.valueOf("")
        : IStringItem.type().ofType(arguments.get(1).getFirstItem(true));

    return ISequence.of(IStringItem.valueOf(fnSubstringBefore(arg1.asString(), arg2.asString())));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-substring-before">fn:substring-before</a>.
   *
   * @param arg1
   *          the source string to get a substring from
   * @param arg2
   *          the substring to match and find the substring to return before the
   *          match
   * @return the substring
   */
  @NonNull
  public static String fnSubstringBefore(
      @NonNull String arg1,
      @NonNull String arg2) {
    return ObjectUtils.notNull(StringUtils.substringBefore(arg1, arg2));
  }
}
