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
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-join">array:join</a>
 * function.
 */
public final class ArrayJoin {
  private static final String NAME = "join";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_ARRAY)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("array")
          .type(IArrayItem.type())
          .zeroOrMore()
          .build())
      .returnType(IItem.type())
      .returnZeroOrOne()
      .functionHandler(ArrayJoin::execute)
      .build();

  private ArrayJoin() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends ICollectionValue> ISequence<? extends IArrayItem<T>> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IArrayItem<T>> arrays = arguments.get(0).ofType(IArrayItem.type());
    return join(arrays).toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-join">array:join</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param arrays
   *          the arrays to join
   * @return a new combined array
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> join(
      @NonNull Collection<? extends IArrayItem<T>> arrays) {
    return IArrayItem.ofCollection(ObjectUtils.notNull(arrays.stream()
        .flatMap(Collection::stream)
        .collect(Collectors.toList())));
  }
}
