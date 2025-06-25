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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-substring">fn:substring</a>
 * functions.
 */
public final class FnSubstring {
  private static final String NAME = "substring";
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("sourceString")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("start")
          .type(IDecimalItem.type())
          .one()
          .build())
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnSubstring::executeTwoArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_THREE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("sourceString")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("start")
          .type(IDecimalItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("length")
          .type(IDecimalItem.type())
          .one()
          .build())
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnSubstring::executeThreeArg)
      .build();

  private FnSubstring() {
    // disable construction
  }

  @SuppressWarnings({ "unused", "PMD.OnlyOneReturn" })
  @NonNull
  private static ISequence<IStringItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem sourceString = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));

    if (sourceString == null) {
      return ISequence.of(IStringItem.valueOf(""));
    }

    IDecimalItem start = IDecimalItem.type().ofType(arguments.get(1).getFirstItem(true));

    int startIndex = start.round().toIntValueExact();

    return ISequence.of(IStringItem.valueOf(
        fnSubstring(
            sourceString.asString(),
            startIndex,
            sourceString.asString().length() - Math.max(startIndex, 1) + 1)));
  }

  @SuppressWarnings({ "unused", "PMD.OnlyOneReturn" })
  @NonNull
  private static ISequence<IStringItem> executeThreeArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem sourceString = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));

    if (sourceString == null) {
      return ISequence.of(IStringItem.valueOf(""));
    }

    IDecimalItem start = IDecimalItem.type().ofType(arguments.get(1).getFirstItem(true));
    IDecimalItem length = IDecimalItem.type().ofType(arguments.get(2).getFirstItem(true));

    return ISequence.of(IStringItem.valueOf(
        fnSubstring(
            sourceString.asString(),
            start.round().toIntValueExact(),
            length.round().toIntValueExact())));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-substring">fn:substring</a>.
   *
   * @param source
   *          the source string to get a substring from
   * @param start
   *          the 1-based start location
   * @param length
   *          the substring length
   * @return the substring
   */
  @NonNull
  public static String fnSubstring(
      @NonNull String source,
      int start,
      int length) {
    int sourceLength = source.length();

    // XPath uses 1-based indexing, so subtract 1 for 0-based Java indexing
    int startIndex = Math.max(start, 1);

    // Handle negative or zero length
    int endIndex = length <= 0 ? startIndex : Math.min(start + length, sourceLength + 1);

    // Ensure startIndex is not greater than endIndex
    startIndex = Math.min(startIndex, endIndex);

    return ObjectUtils.notNull(source.substring(startIndex - 1, endIndex - 1));
  }
}
