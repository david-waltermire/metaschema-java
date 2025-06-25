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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-string-join">fn:string-join</a>
 * function.
 */
public final class FnStringJoin {
  private static final String NAME = "string-join";
  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(IAnyAtomicItem.type())
          .oneOrMore()
          .build())
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnStringJoin::execute)
      .build();

  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("arg2")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnStringJoin::execute)
      .build();

  private FnStringJoin() {
    // disable construction
  }

  @SuppressWarnings({ "unused", "PMD.OnlyOneReturn" })
  @NonNull
  private static ISequence<IStringItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    ISequence<IAnyAtomicItem> arg1 = arguments.get(0).ofType(IAnyAtomicItem.type());
    IStringItem arg2 = arguments.size() == 1
        ? IStringItem.valueOf("")
        : IStringItem.type().ofTypeOrNull(arguments.get(1).getFirstItem(true));

    if (arg1.isEmpty()) {
      return ISequence.of(IStringItem.valueOf(""));
    }

    return ISequence.of(fnStringJoin(ObjectUtils.notNull(arg1), arg2));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-string-join">fn:string-join</a>.
   *
   * @param items
   *          the items to join in string form
   * @param separator
   *          the optional separator to use between joined items
   * @return the atomized result
   */
  @NonNull
  public static IStringItem fnStringJoin(
      @NonNull List<? extends IAnyAtomicItem> items,
      @Nullable IStringItem separator) {
    return IStringItem.valueOf(stringJoin(
        ObjectUtils.notNull(items.stream().map(item -> item == null ? "" : IStringItem.cast(item).asString())),
        separator == null ? "" : separator.asString()));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-string-join">fn:string-join</a>.
   *
   * @param items
   *          the items to join in string form
   * @param separator
   *          the optional separator to use between joined items
   * @return the atomized result
   */
  @NonNull
  private static String stringJoin(
      @NonNull Stream<String> items,
      @NonNull String separator) {
    return ObjectUtils.notNull(items.collect(Collectors.joining(separator)));
  }
}
