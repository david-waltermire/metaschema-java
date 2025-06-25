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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-map-keys">map:keys</a>
 * function.
 */
public final class MapKeys {
  private static final String NAME = "keys";
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
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrMore()
      .functionHandler(MapKeys::execute)
      .build();

  private MapKeys() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IMapItem<?> map = IMapItem.type().ofType(arguments.get(0).getFirstItem(true));

    return ISequence.of(keys(map));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-keys">map:keys</a>.
   *
   * @param map
   *          the map to get the keys for
   * @return a stream of map keys
   */
  @SuppressWarnings("null")
  @NonNull
  public static Stream<IAnyAtomicItem> keys(@NonNull Map<IMapKey, ?> map) {
    return map.keySet().stream()
        .map(IMapKey::getKey);
  }
}
