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
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-put">array:put</a>
 * function.
 */
public final class ArrayPut {
  @NonNull
  private static final String NAME = "put";
  // CPD-OFF
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
      .argument(IArgument.builder()
          .name("member")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(ArrayPut::execute)
      .build();
  // CPD-ON

  private ArrayPut() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends ICollectionValue> ISequence<? extends IArrayItem<T>> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<T> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    IIntegerItem position = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));
    @SuppressWarnings("unchecked")
    T member = (T) arguments.get(2).toCollectionValue();

    return put(array, position, member).toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-put">array:put</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param positionItem
   *          the integer position of the item to replace
   * @param member
   *          the Metapath item to replace the identified array member with
   * @return a new array containing the modification
   * @throws NegativeLengthArrayMetapathException
   *           if the position is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> put(
      @NonNull IArrayItem<T> array,
      @NonNull IIntegerItem positionItem,
      @NonNull T member) {
    return put(array, positionItem.toIntValueExact(), member);
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-put">array:put</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param position
   *          the integer position of the item to replace
   * @param member
   *          the Metapath item to replace the identified array member with
   * @return a new array containing the modification
   * @throws NegativeLengthArrayMetapathException
   *           if the position is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> put(
      @NonNull IArrayItem<T> array,
      int position,
      @NonNull T member) {
    List<T> copy = new ArrayList<>(array);
    try {
      copy.set(position - 1, member);
    } catch (IndexOutOfBoundsException ex) {
      throw new IndexOutOfBoundsArrayMetapathException(
          array,
          String.format("The position %d is outside the range of values for the array of size '%d'.",
              position,
              copy.size()),
          ex);
    }

    return IArrayItem.ofCollection(copy);
  }
}
