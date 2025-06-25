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
import gov.nist.secauto.metaschema.core.metapath.item.function.NegativeLengthArrayMetapathException;

import java.util.ArrayList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-subarray">array:subarray</a>
 * function.
 */
public final class ArraySubarray {
  private static final String NAME = "subarray";
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
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
          .name("start")
          .type(IIntegerItem.type())
          .one()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(ArraySubarray::executeTwoArg)
      .build();
  @NonNull
  static final IFunction SIGNATURE_THREE_ARG = IFunction.builder()
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
          .name("start")
          .type(IIntegerItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("length")
          .type(IIntegerItem.type())
          .one()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(ArraySubarray::executeThreeArg)
      .build();

  private ArraySubarray() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends ICollectionValue> ISequence<IArrayItem<T>> executeTwoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<T> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    IIntegerItem start = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));

    return ISequence.of(subarray(array, start));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends ICollectionValue> ISequence<IArrayItem<T>> executeThreeArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<T> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    IIntegerItem start = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));
    IIntegerItem length = IIntegerItem.type().ofType(arguments.get(2).getFirstItem(true));

    return ISequence.of(subarray(array, start, length));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-subarray">array:subarray</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param startItem
   *          the integer position of the item to start with (inclusive)
   * @return a new array item consisting of the items in the identified range
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the start position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> subarray(
      @NonNull IArrayItem<T> array,
      @NonNull IIntegerItem startItem) {
    return subarray(array, startItem.toIntValueExact());
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-subarray">array:subarray</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param startItem
   *          the integer position of the item to start with (inclusive)
   * @param lengthItem
   *          the integer count of items to include starting with the item at the
   *          start position
   * @return a new array item consisting of the items in the identified range
   * @throws NegativeLengthArrayMetapathException
   *           if the length is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the start position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> subarray(
      @NonNull IArrayItem<T> array,
      @NonNull IIntegerItem startItem,
      @NonNull IIntegerItem lengthItem) {
    return subarray(array, startItem.toIntValueExact(), lengthItem.toIntValueExact());
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-subarray">array:subarray</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param start
   *          the integer position of the item to start with (inclusive)
   * @return a new array item consisting of the items in the identified range
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the start position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> subarray(
      @NonNull IArrayItem<T> array,
      int start) {
    return subarray(array, start, array.size() - start + 1);
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-subarray">array:subarray</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param start
   *          the integer position of the item to start with (inclusive)
   * @param length
   *          the integer count of items to include starting with the item at the
   *          start position
   * @return a new array item consisting of the items in the identified range
   * @throws NegativeLengthArrayMetapathException
   *           if the length argument is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position of the start argument is not a value in the range
   *           of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> subarray(
      @NonNull IArrayItem<T> array,
      int start,
      int length) {
    if (length < 0) {
      throw new NegativeLengthArrayMetapathException(
          array,
          String.format("The length '%d' is negative.", length));
    }

    List<T> copy;
    try {
      copy = array.subList(start - 1, start - 1 + length);
    } catch (IndexOutOfBoundsException ex) {
      throw new IndexOutOfBoundsArrayMetapathException(
          array,
          String.format("The start + length (%d + %d) exceeds the array length '%d'.",
              start,
              length,
              array.size()),
          ex);
    }

    return IArrayItem.ofCollection(new ArrayList<>(copy));
  }
}
