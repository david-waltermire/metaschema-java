/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-substring">fn:substring</a>.
 */
public final class FnSubstring {
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name("substring")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("sourceString")
          .type(IStringItem.class)
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("start")
          .type(IDecimalItem.class)
          .one()
          .build())
      .returnType(IStringItem.class)
      .returnOne()
      .functionHandler(FnSubstring::executeTwoArg)
      .build();

  static final IFunction SIGNATURE_THREE_ARG = IFunction.builder()
      .name("substring")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("sourceString")
          .type(IStringItem.class)
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("start")
          .type(IDecimalItem.class)
          .one()
          .build())
      .argument(IArgument.builder()
          .name("length")
          .type(IDecimalItem.class)
          .one()
          .build())
      .returnType(IStringItem.class)
      .returnOne()
      .functionHandler(FnSubstring::executeThreeArg)
      .build();

  private FnSubstring() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem sourceString = FunctionUtils.asTypeOrNull(arguments.get(0).getFirstItem(true));

    if (sourceString == null) {
      return ISequence.of(IStringItem.valueOf(""));
    }

    IDecimalItem start = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(1).getFirstItem(true)));

    int startIndex = start.round().asInteger().intValue();

    return ISequence.of(fnSubstring(
      sourceString.asString(),
      startIndex,
      sourceString.toString().length() - Math.max(startIndex,1) + 1));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeThreeArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem sourceString = FunctionUtils.asTypeOrNull(arguments.get(0).getFirstItem(true));

    if (sourceString == null) {
      return ISequence.of(IStringItem.valueOf(""));
    }

    IDecimalItem start = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(1).getFirstItem(true)));
    IDecimalItem length = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(2).getFirstItem(true)));

    return ISequence.of(fnSubstring(
      sourceString.asString(),
      start.round().asInteger().intValue(),
      length.round().asInteger().intValue()));
  }

    /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-substring">fn:substring</a>.
   *
   * @param sourceString
   *
   * @param start
   *
   * @param length
   *
   * @return the atomized result
   */
  @NonNull
  public static IStringItem fnSubstring(
    @NonNull String source,
    @NonNull int start,
    @NonNull int length) {
    int sourceLength = source.length();

    // XPath uses 1-based indexing, so subtract 1 for 0-based Java indexing
    int startIndex = Math.max(start, 1);

    // Handle negative or zero length
    int endIndex = length <= 1 ? startIndex : Math.min(startIndex + length, sourceLength);
    
    // Ensure startIndex is not greater than endIndex
    startIndex = Math.min(startIndex, endIndex);
    
    return IStringItem.valueOf(source.substring(startIndex-1, endIndex));
  }
}
