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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IndexOutOfBoundsArrayMetapathException;
import gov.nist.secauto.metaschema.core.metapath.item.function.NegativeLengthArrayMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-remove">array:remove</a>
 * function.
 */
public final class ArrayRemove {
  private static final String NAME = "remove";
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
          .name("positions")
          .type(IIntegerItem.type())
          .zeroOrMore()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(ArrayRemove::execute)
      .build();

  private ArrayRemove() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends IItem> ISequence<IArrayItem<T>> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<T> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    ISequence<IIntegerItem> positions = arguments.get(1).ofType(IIntegerItem.type());
    return ISequence.of(removeItems(array, positions));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-remove">array:remove</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param positions
   *          the integer position of the items to remove
   * @return a new array containing the modification
   * @throws NegativeLengthArrayMetapathException
   *           if the position is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends IItem> IArrayItem<T> removeItems(
      @NonNull IArrayItem<T> array,
      @NonNull Collection<? extends IIntegerItem> positions) {
    int size = array.size();
    return remove(
        array,
        ObjectUtils.notNull(positions.stream()
            .map(IIntegerItem::toIntValueExact)
            .peek(position -> {
              if (position < 1 || position > size) {
                throw new ArrayIndexOutOfBoundsException(
                    String.format("Index position '%d' is out of bounds for the array of size '%d'.", position, size));
              }
            })
            .collect(Collectors.toSet())));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-remove">array:remove</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param positions
   *          the integer position of the items to remove
   * @return a new array containing the modification
   * @throws NegativeLengthArrayMetapathException
   *           if the position is negative
   * @throws IndexOutOfBoundsArrayMetapathException
   *           if the position is not in the range of 1 to array:size
   */
  @NonNull
  public static <T extends IItem> IArrayItem<T> remove(
      @NonNull IArrayItem<T> array,
      @NonNull Collection<Integer> positions) {
    Set<Integer> positionSet = positions instanceof Set ? (Set<Integer>) positions : new HashSet<>(positions);

    List<T> remaining = ObjectUtils.notNull(IntStream.range(1, array.size() + 1)
        .filter(index -> !positionSet.contains(index))
        .mapToObj(index -> array.get(index - 1))
        .collect(Collectors.toList()));

    return IArrayItem.ofCollection(remaining);
  }
}
