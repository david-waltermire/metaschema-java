/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.JsonFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-map-merge">map:merge</a>
 * functions.
 */
public final class MapMerge {
  private static final String NAME = "merge";
  private static final Random RANDOM = new Random();
  private static final IMapKey DUPLICATES_OPTION = IStringItem.valueOf("duplicates").asMapKey();

  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_MAP)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("maps")
          .type(IMapItem.type())
          .zeroOrMore()
          .build())
      .returnType(IMapItem.type())
      .returnOne()
      .functionHandler(MapMerge::executeOneArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_MAP)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("maps")
          .type(IMapItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("options")
          .type(IMapItem.type())
          .one()
          .build())
      .returnType(IMapItem.type())
      .returnOne()
      .functionHandler(MapMerge::executeTwoArg)
      .build();

  private enum Duplicates {
    REJECT("reject", (key, v1, v2) -> {
      throw new JsonFunctionException(
          JsonFunctionException.DUPLICATE_KEYS,
          String.format("Duplicate key '%s' not allowed.", key.getKey().asString()));
    }),

    USE_FIRST("use-first", (key, v1, v2) -> v1),
    USE_LAST("use-last", (key, v1, v2) -> v2),
    USE_ANY("use-any", (key, v1, v2) -> RANDOM.nextBoolean() ? v1 : v2),
    @SuppressWarnings("checkstyle:Indentation")
    COMBINE(
        "combine",
        (key, v1, v2) -> Stream.concat(v1.toSequence().stream(), v2.toSequence().stream())
            .collect(CustomCollectors.toSequence()));

    private static final Map<String, Duplicates> BY_NAME;

    @NonNull
    private final String name;
    @NonNull
    private final CustomCollectors.DuplicateHandler<IMapKey, ICollectionValue> duplicateHander;

    static {
      @SuppressWarnings("PMD.UseConcurrentHashMap")
      Map<String, Duplicates> map = new HashMap<>();
      for (Duplicates value : values()) {
        map.put(value.getName(), value);
      }
      BY_NAME = Collections.unmodifiableMap(map);
    }

    @Nullable
    public static Duplicates lookup(@NonNull String name) {
      return BY_NAME.get(name);
    }

    Duplicates(@NonNull String name,
        @NonNull CustomCollectors.DuplicateHandler<IMapKey, ICollectionValue> duplicateHander) {
      this.name = name;
      this.duplicateHander = duplicateHander;
    }

    public String getName() {
      return name;
    }

    public CustomCollectors.DuplicateHandler<IMapKey, ICollectionValue> getDuplicateHander() {
      return duplicateHander;
    }
  }

  private MapMerge() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IMapItem<?>> maps = arguments.get(0).ofType(IMapItem.type());

    return ISequence.of(merge(maps, CollectionUtil.emptyMap()));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> executeTwoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IMapItem<?>> maps = arguments.get(0).ofType(IMapItem.type());
    IMapItem<?> options = IMapItem.type().ofType(arguments.get(1).getFirstItem(true));

    return ISequence.of(merge(maps, options));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-map-merge">map:merge</a>.
   *
   * @param maps
   *          a collection of maps to merge
   * @param options
   *          settings that affect the merge behavior
   * @return a map containing the merged entries
   */
  @SuppressWarnings({ "null", "PMD.OnlyOneReturn" })
  @NonNull
  public static IMapItem<?> merge(@NonNull Collection<? extends Map<IMapKey, ? extends ICollectionValue>> maps,
      @NonNull Map<IMapKey, ? extends ICollectionValue> options) {
    if (maps.isEmpty()) {
      return IMapItem.empty();
    }

    // handle the "duplicates" option
    ICollectionValue duplicatesOption = options.get(DUPLICATES_OPTION);

    Duplicates duplicates;
    if (duplicatesOption == null) {
      // default option
      duplicates = Duplicates.USE_FIRST;
    } else {
      // resolve the provided option
      IAnyAtomicItem atomicValue = ISequence.of(duplicatesOption.toSequence().atomize()).getFirstItem(true);
      if (atomicValue == null) {
        throw new JsonFunctionException(
            JsonFunctionException.INVALID_OPTION,
            String.format("Missing '%s' option value.", DUPLICATES_OPTION.getKey().asString()));
      }
      String duplicatesValue = IStringItem.cast(atomicValue).asString();
      duplicates = Duplicates.lookup(duplicatesValue);
      if (duplicates == null) {
        throw new JsonFunctionException(
            JsonFunctionException.INVALID_OPTION,
            String.format("Invalid '%s' option value '%s'.", DUPLICATES_OPTION.getKey().asString(), duplicatesValue));
      }
    }

    // merge the maps
    return IMapItem.ofCollection(maps.stream()
        .flatMap(map -> map.entrySet().stream())
        // collect the entries into a new map
        .collect(CustomCollectors.toMap(Map.Entry::getKey, Map.Entry::getValue, duplicates.getDuplicateHander(),
            HashMap::new)));
  }
}
