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
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.function.BiFunction;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-map-for-each">map:for-each</a>
 * function.
 */
public final class MapForEach {
  private static final String NAME = "for-each";
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
          .name("action")
          .type(IFunction.type())
          .one()
          .build())
      .returnType(IItem.type())
      .returnZeroOrMore()
      .functionHandler(MapForEach::execute)
      .build();

  private MapForEach() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IMapItem<?> map = IMapItem.type().ofType(arguments.get(0).getFirstItem(true));
    IFunction action = IFunction.type().ofType(arguments.get(1).getFirstItem(true));

    BiFunction<IAnyAtomicItem, ISequence<?>, ISequence<?>> lambda = adaptFunction(action, dynamicContext);
    return forEach(map, lambda);
  }

  /**
   * Adapts the provided function call to a lambda expression for use with
   * {@link #forEach(IMapItem, BiFunction)}.
   *
   * @param function
   *          the function to adapt
   * @param dynamicContext
   *          the dynamic context for use in evaluating the function
   * @return a lambda expression
   */
  @NonNull
  private static BiFunction<IAnyAtomicItem, ISequence<?>, ISequence<?>> adaptFunction(
      @NonNull IFunction function,
      @NonNull DynamicContext dynamicContext) {
    return (key, value) -> {
      List<ISequence<?>> arguments = ObjectUtils.notNull(List.of(
          ISequence.of(key),
          value.toSequence()));

      return function.execute(arguments, dynamicContext, ISequence.empty());
    };
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-for-each">map:for-each</a>.
   *
   * @param map
   *          the map of Metapath items that is the target of retrieval
   * @param action
   *          the action to perform on each entry in the map
   * @return a stream resulting from concatenating the resulting streams provided
   *         by the action result
   */
  @NonNull
  public static ISequence<?> forEach(
      @NonNull IMapItem<?> map,
      @NonNull BiFunction<IAnyAtomicItem, ISequence<?>, ISequence<?>> action) {
    return ISequence.of(ObjectUtils.notNull(map.entrySet().stream()
        .flatMap(entry -> {
          IAnyAtomicItem key = entry.getKey().getKey();
          ISequence<?> values = entry.getValue().contentsAsSequence();
          return action.apply(key, values).stream();
        })));
  }
}
