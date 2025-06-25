/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.ComparisonFunctions;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidArgumentFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBase64BinaryItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IUntypedAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1
 * <a href="https://www.w3.org/TR/xpath-functions-31/#func-min">fn:min</a> and
 * <a href="https://www.w3.org/TR/xpath-functions-31/#func-max">fn:max</a>
 * functions.
 */
public final class FnMinMax {
  private static final String NAME_MIN = "min";
  private static final String NAME_MAX = "max";
  /**
   * Defines the set of primitive atomic item types supported by the min/max
   * functions. This set is used for type validation and normalization during
   * comparison operations.
   */
  @NonNull
  private static final Set<Class<? extends IAnyAtomicItem>> PRIMITIVE_ITEM_TYPES = ObjectUtils.notNull(Set.of(
      IStringItem.class,
      IBooleanItem.class,
      IDecimalItem.class,
      IDurationItem.class,
      IDateTimeItem.class,
      IDateItem.class,
      IBase64BinaryItem.class,
      IAnyUriItem.class));
  @NonNull
  static final IFunction SIGNATURE_MIN = IFunction.builder()
      .name(NAME_MIN)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrOne()
      .functionHandler(FnMinMax::executeMin)
      .build();

  @NonNull
  static final IFunction SIGNATURE_MAX = IFunction.builder()
      .name(NAME_MAX)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnZeroOrOne()
      .functionHandler(FnMinMax::executeMax)
      .build();

  private FnMinMax() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeMin(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> sequence = arguments.get(0).ofType(IAnyAtomicItem.type());
    return ISequence.of(min(sequence));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeMax(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> sequence = arguments.get(0).ofType(IAnyAtomicItem.type());
    return ISequence.of(max(sequence));
  }

  /**
   * An implementation of XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-min">fn:min</a>.
   *
   * @param items
   *          the items to find the minimum value for
   * @return the average
   */
  @Nullable
  public static IAnyAtomicItem min(@NonNull List<? extends IAnyAtomicItem> items) {
    // FIXME: support implicit timezone
    return normalize(items)
        .reduce(null, (item1, item2) -> item1 != null && ComparisonFunctions.valueCompairison(
            item1,
            ComparisonFunctions.Operator.LE,
            ObjectUtils.notNull(item2),
            new DynamicContext()).toBoolean()
                ? item1
                : item2);
  }

  /**
   * An implementation of XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-max">fn:max</a>.
   *
   * @param items
   *          the items to find the maximum value for
   * @return the average
   */
  @Nullable
  public static IAnyAtomicItem max(@NonNull List<? extends IAnyAtomicItem> items) {
    // FIXME: support implicit timezone
    return normalize(items)
        .reduce(null, (item1, item2) -> item1 != null && ComparisonFunctions.valueCompairison(
            item1,
            ComparisonFunctions.Operator.GE,
            ObjectUtils.notNull(item2),
            new DynamicContext()).toBoolean()
                ? item1
                : item2);
  }

  @SuppressWarnings("PMD.OnlyOneReturn") // readability
  private static Stream<? extends IAnyAtomicItem> normalize(
      @NonNull List<? extends IAnyAtomicItem> items) {
    if (items.isEmpty()) {
      return Stream.empty();
    }

    if (items.size() == 1) {
      return Stream.of(items.get(0));
    }

    List<? extends IAnyAtomicItem> resultingItems = convertUntypedItems(items);
    Map<Class<? extends IAnyAtomicItem>, Integer> counts = countItemTypes(resultingItems);
    return createNormalizedStream(resultingItems, counts);
  }

  @NonNull
  private static List<? extends IAnyAtomicItem> convertUntypedItems(
      @NonNull List<? extends IAnyAtomicItem> items) {
    return ObjectUtils.notNull(items.stream()
        .map(item -> item instanceof IUntypedAtomicItem ? IDecimalItem.cast(item) : item)
        .collect(Collectors.toList()));
  }

  @NonNull
  private static Map<Class<? extends IAnyAtomicItem>, Integer> countItemTypes(
      @NonNull List<? extends IAnyAtomicItem> items) {
    return FunctionUtils.countTypes(PRIMITIVE_ITEM_TYPES, items);
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  private static Stream<? extends IAnyAtomicItem> createNormalizedStream(
      @NonNull List<? extends IAnyAtomicItem> items,
      @NonNull Map<Class<? extends IAnyAtomicItem>, Integer> counts) {

    // Single type - no conversion needed
    if (counts.size() == 1) {
      return ObjectUtils.notNull(items.stream());
    }

    // Multiple types - attempt conversion
    int size = items.size();
    if (counts.size() > 1) {
      // Check if all items are either String or AnyUri
      if (counts.getOrDefault(IStringItem.class, 0) + counts.getOrDefault(IAnyUriItem.class, 0) == size) {
        return ObjectUtils.notNull(items.stream().map(IAnyAtomicItem::asStringItem));
      }

      // Check if all items are Decimal
      if (counts.getOrDefault(IDecimalItem.class, 0) == size) {
        return ObjectUtils.notNull(items.stream().map(item -> (IDecimalItem) item));
      }
    }

    // No valid conversion possible
    throw new InvalidArgumentFunctionException(
        InvalidArgumentFunctionException.INVALID_ARGUMENT_TYPE,
        String.format(
            "Values must all be of a single atomic type. Found multiple types: [%s]",
            IItem.getTypes(items).stream()
                .map(IItemType::toSignature)
                .collect(Collectors.joining(", "))));
  }
}
