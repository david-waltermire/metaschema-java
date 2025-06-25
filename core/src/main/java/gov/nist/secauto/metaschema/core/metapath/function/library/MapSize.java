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
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-map-size">map:size</a>
 * function.
 */
public final class MapSize {
  private static final String NAME = "size";
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
      .returnType(IIntegerItem.type())
      .returnOne()
      .functionHandler(MapSize::execute)
      .build();

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-size">map:size</a>.
   *
   * @param array
   *          the arrays to join
   * @return a new combined array
   */
  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IMapItem<?> map = IMapItem.type().ofType(arguments.get(0).getFirstItem(true));
    return ISequence.of(IIntegerItem.valueOf(map.size()));
  }

  private MapSize() {
    // disable
  }
}
