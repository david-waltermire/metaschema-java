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
          // Review if xs:double to IIntegerItem data-type mapping appropriate?
          .type(IDecimalItem.class)
          .one()
          .build())
      .returnType(IStringItem.class)
      .returnOne()
      .functionHandler(FnSubstring::execute)
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
          // Review if xs:double to IIntegerItem data-type mapping appropriate?
          .type(IDecimalItem.class)
          .one()
          .build())
      .argument(IArgument.builder()
          .name("length")
          // Review if xs:double to IIntegerItem data-type mapping appropriate?
          .type(IDecimalItem.class)
          .one()
          .build())
      .returnType(IStringItem.class)
      .returnOne()
      .functionHandler(FnSubstring::execute)
      .build();

  private FnSubstring() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem sourceString = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(0).getFirstItem(true)));
    IDecimalItem start = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(1).getFirstItem(true)));
    IDecimalItem length = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(2).getFirstItem(true)));
    return ISequence.of(substring(sourceString, start, length));
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
  public static IStringItem substring(@NonNull IStringItem sourceString, @NonNull IDecimalItem start, @NonNull IDecimalItem length) {
    int startIndex = start.asInteger().intValue() - 1;
    int endIndex = startIndex + length.asInteger().intValue();
    return IStringItem.valueOf(sourceString.toString().substring(startIndex, endIndex));
  }
}
