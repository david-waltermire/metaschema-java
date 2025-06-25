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
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-map-put">map:put</a>
 * function.
 */
public final class MapPut {
  private static final String NAME = "put";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_MAP)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("map")
          .type(IMapItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("key")
          .type(IAnyAtomicItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("value")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IMapItem.type())
      .returnOne()
      .functionHandler(MapPut::execute)
      .build();

  private MapPut() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <V extends ICollectionValue> ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IMapItem<V> map = IMapItem.type().ofType(arguments.get(0).getFirstItem(true));
    IAnyAtomicItem key = IAnyAtomicItem.type().ofType(arguments.get(1).getFirstItem(true));
    @SuppressWarnings("unchecked")
    V value = (V) ObjectUtils.requireNonNull(arguments.get(2)).toCollectionValue();

    return put(map, key, value).toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-put">map:put</a>.
   *
   * @param <V>
   *          the type of items in the given Metapath map
   * @param map
   *          the map of Metapath items that is to be modified
   * @param key
   *          the key for the value to add to the map
   * @param value
   *          the value to add to the map
   * @return the modified map
   */
  @NonNull
  public static <V extends ICollectionValue> IMapItem<V> put(
      @NonNull IMapItem<V> map,
      @NonNull IAnyAtomicItem key,
      @NonNull V value) {
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    Map<IMapKey, V> copy = new HashMap<>(map);
    copy.put(key.asMapKey(), value);

    return IMapItem.ofCollection(copy);
  }
}
