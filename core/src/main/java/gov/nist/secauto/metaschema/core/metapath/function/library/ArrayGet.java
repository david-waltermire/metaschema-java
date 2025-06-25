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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IndexOutOfBoundsArrayMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-get">array:get</a>
 * function.
 */
public final class ArrayGet {
  private static final String NAME = "get";
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
      .argument(IArgument.builder()
          .name("position")
          .type(IIntegerItem.type())
          .one()
          .build())
      .returnType(IItem.type())
      .returnZeroOrOne()
      .functionHandler(ArrayGet::execute)
      .build();

  private ArrayGet() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<?> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    IIntegerItem position = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));

    return get(array, position).toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-get">array:get</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param target
   *          the array of Metapath items that is the target of retrieval
   * @param positionItem
   *          the integer position of the item to retrieve
   * @return the retrieved item
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> T get(
      @NonNull IArrayItem<T> target,
      @NonNull IIntegerItem positionItem) {
    return get(target, positionItem.toIntValueExact());
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-get">array:get</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param target
   *          the array of Metapath items that is the target of retrieval
   * @param position
   *          the integer position of the item to retrieve
   * @return the retrieved item
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> T get(
      @NonNull IArrayItem<T> target,
      int position) {
    try {
      return ObjectUtils.requireNonNull(target.get(position - 1));
    } catch (IndexOutOfBoundsException ex) {
      throw new IndexOutOfBoundsArrayMetapathException(
          target,
          String.format("The index %d is outside the range of values for the array size '%d'.",
              position,
              target.size()),
          ex);
    }
  }
}
