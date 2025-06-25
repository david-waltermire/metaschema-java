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
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-map-find">map:find</a>
 * function.
 */
public final class MapFind {
  private static final String NAME = "find";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_MAP)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("input")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("key")
          .type(IAnyAtomicItem.type())
          .one()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(MapFind::execute)
      .build();

  private MapFind() {
    // disable construction
  }

  @SuppressWarnings({ "unused", "PMD.OnlyOneReturn" })
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<?> input = ObjectUtils.requireNonNull(arguments.get(0));
    if (input.isEmpty()) {
      return ISequence.of(IArrayItem.empty());
    }

    IAnyAtomicItem key = IAnyAtomicItem.type().ofType(arguments.get(1).getFirstItem(true));

    return ISequence.of(IArrayItem.ofCollection(
        ObjectUtils.notNull(find((Collection<? extends IItem>) input, key)
            .collect(Collectors.toList()))));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-find">map:find</a>.
   *
   * @param items
   *          the item sequence to search for key matches
   * @param key
   *          the key for the item to retrieve
   * @return the retrieved item
   */
  @NonNull
  public static Stream<ICollectionValue> find(
      @NonNull Collection<? extends IItem> items,
      @NonNull IAnyAtomicItem key) {
    return ObjectUtils.notNull(items.stream()
        // handle item
        .flatMap(item -> find(ObjectUtils.notNull(item), key)));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-find">map:find</a>.
   *
   * @param item
   *          the item to search for key matches
   * @param key
   *          the key for the item to retrieve
   * @return the retrieved item
   */
  @NonNull
  public static Stream<ICollectionValue> find(
      @NonNull IItem item,
      @NonNull IAnyAtomicItem key) {
    Stream<ICollectionValue> retval;
    if (item instanceof IArrayItem) {
      IArrayItem<?> array = (IArrayItem<?>) item;
      retval = ObjectUtils.notNull(array.stream()
          // handle array values
          .flatMap(value -> find(ObjectUtils.notNull(value), key)));
    } else if (item instanceof IMapItem) {
      IMapItem<?> map = (IMapItem<?>) item;
      // handle map
      retval = find(map, key);
    } else {
      // do nothing
      retval = ObjectUtils.notNull(Stream.empty());
    }
    return retval;
  }

  @NonNull
  private static Stream<ICollectionValue> find(
      @NonNull ICollectionValue value,
      @NonNull IAnyAtomicItem key) {
    Stream<ICollectionValue> retval;
    if (value instanceof ISequence) {
      ISequence<?> sequence = (ISequence<?>) value;
      // handle sequence items
      retval = find((Collection<? extends IItem>) sequence, key);
    } else {
      // handle item
      retval = find((IItem) value, key);
    }
    return retval;
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-find">map:find</a>.
   * <p>
   * This is a specialized method for processing an item that is a map item, which
   * can be searched for a key in a much more efficient way.
   *
   * @param item
   *          the item to search for key matches
   * @param key
   *          the key for the item to retrieve
   * @return the retrieved item
   */
  @NonNull
  public static Stream<ICollectionValue> find(
      @NonNull IMapItem<?> item,
      @NonNull IAnyAtomicItem key) {
    return ObjectUtils.notNull(Stream.concat(
        // add matching value, if it exists
        Stream.ofNullable(MapGet.get(item, key)),
        item.values().stream()
            // handle map values
            .flatMap(value -> find(ObjectUtils.notNull(value), key))));
  }
}
