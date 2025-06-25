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

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-map-get">map:get</a>
 * function.
 */
public final class MapGet {
  private static final String NAME = "get";
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
      .returnType(IItem.type())
      .returnZeroOrOne()
      .functionHandler(MapGet::execute)
      .build();

  private MapGet() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IMapItem<?> map = IMapItem.type().ofType(arguments.get(0).getFirstItem(true));
    IAnyAtomicItem key = IAnyAtomicItem.type().ofType(arguments.get(1).getFirstItem(true));

    ICollectionValue value = get(map, key);
    return value == null ? ISequence.empty() : value.toSequence();
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-get">map:get</a>.
   *
   * @param <V>
   *          the type of items in the given Metapath map
   * @param map
   *          the map of Metapath items that is the target of retrieval
   * @param key
   *          the key for the item to retrieve
   * @return the retrieved item
   */
  @Nullable
  public static <V extends ICollectionValue> V get(
      @NonNull IMapItem<V> map,
      @NonNull IAnyAtomicItem key) {
    return map.get(key.asMapKey());
  }
}
