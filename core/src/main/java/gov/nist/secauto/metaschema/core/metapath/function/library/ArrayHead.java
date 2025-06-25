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

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-head">array:head</a>
 * function.
 */
public final class ArrayHead {
  private static final String NAME = "head";
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
          .one()
          .build())
      .returnType(IItem.type())
      .returnZeroOrOne()
      .functionHandler(ArrayHead::execute)
      .build();

  private ArrayHead() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<?> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));

    ICollectionValue result = head(array);
    return result == null ? ISequence.empty() : result.toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-head">array:head</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the array to get the head item from
   * @return the head item
   */
  @Nullable
  public static <T extends ICollectionValue> T head(@NonNull IArrayItem<T> array) {
    return array.isEmpty() ? null : array.get(0);
  }
}
