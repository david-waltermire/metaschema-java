/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-distinct-values">fn:distinct-values</a>
 * functions. This implementation does not implement the two-arg variant with
 * collation at this time.
 */
public final class FnDistinctValues {
  @NonNull
  private static final String NAME = "distinct-values";
  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrMore()
      .functionHandler(FnDistinctValues::executeOneArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> seq = arguments.get(0).ofType(IAnyAtomicItem.type());
    return ISequence.of(fnDistinctValues(seq, dynamicContext));
  }

  /**
   * Get the first occurrence of each distinct value in the provided list.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-distinct-values">fn:distinct-values</a>
   * function.
   *
   * @param values
   *          the items to get destinct values for
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return a the list of distinct values
   */
  @NonNull
  public static Stream<IAnyAtomicItem> fnDistinctValues(
      @NonNull List<IAnyAtomicItem> values,
      @NonNull DynamicContext dynamicContext) {
    return ObjectUtils.notNull(values.stream()
        .filter(ICollectionValue.distinctByDeepEquals(IAnyAtomicItem.class, dynamicContext)));
  }

  private FnDistinctValues() {
    // disable construction
  }
}
