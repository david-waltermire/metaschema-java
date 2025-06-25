/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A collection of utility functions for use in implementing Metapath functions.
 * <p>
 * This class is thread-safe as all methods are stateless and the internal
 * constant is immutable.
 */
// FIXME: Remove these methods in favor of direct calls to methods on the item
// types
public final class FunctionUtils {
  private FunctionUtils() {
    // disable
  }

  /**
   * Gets the first item of the provided sequence as a {@link INumericItem} value.
   * If the sequence is empty, then a {@code null} value is returned.
   * <p>
   * Use {@link ISequence#toNumeric(boolean)} instead.
   *
   * @param sequence
   *          a Metapath sequence containing the value to convert
   * @param requireSingleton
   *          if {@code true} then a {@link TypeMetapathException} is thrown if
   *          the sequence contains more than one item
   * @return the numeric item value, or {@code null} if the result is an empty
   *         sequence
   * @throws TypeMetapathException
   *           if the sequence contains more than one item, or the item cannot be
   *           cast to a numeric value
   *
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @Nullable
  public static INumericItem toNumeric(@NonNull ISequence<?> sequence, boolean requireSingleton) {
    IItem item = sequence.getFirstItem(requireSingleton);
    return item == null ? null : toNumeric(item);
  }

  /**
   * Gets the provided item value as a {@link INumericItem} value.
   * <p>
   * Use {@link IItem#toNumeric()} instead.
   *
   * @param item
   *          the value to convert
   * @return the numeric item value
   * @throws TypeMetapathException
   *           if the sequence contains more than one item, or the item cannot be
   *           cast to a numeric value
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static INumericItem toNumeric(@NonNull IItem item) {
    // atomize
    IAnyAtomicItem atomicItem = ISequence.getFirstItem(item.atomize(), true);
    if (atomicItem == null) {
      throw new InvalidTypeMetapathException(item, "Unable to cast null item");
    }
    return toNumeric(atomicItem);
  }

  /**
   * Gets the provided item value as a {@link INumericItem} value.
   * <p>
   * Use {@link IItem#toNumeric()} instead.
   *
   * @param item
   *          the value to convert
   * @return the numeric item value
   * @throws TypeMetapathException
   *           if the item cannot be cast to a numeric value
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static INumericItem toNumeric(@NonNull IAnyAtomicItem item) {
    try {
      return IDecimalItem.cast(item);
    } catch (InvalidValueForCastFunctionException ex) {
      throw new InvalidTypeMetapathException(item, ex.getLocalizedMessage(), ex);
    }
  }

  /**
   * Gets the provided item value as a {@link INumericItem} value. If the item is
   * {@code null}, then a {@code null} value is returned.
   * <p>
   * Use {@link IAnyAtomicItem#toNumeric()} instead.
   *
   * @param item
   *          the value to convert
   * @return the numeric item value
   * @throws TypeMetapathException
   *           if the item cannot be cast to a numeric value
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @Nullable
  public static INumericItem toNumericOrNull(@Nullable IAnyAtomicItem item) {
    return item == null ? null : toNumeric(item);
  }

  /**
   * Casts the provided {@code item} as the result type, if the item is not
   * {@code null}.
   * <p>
   * Use {@link IItemType#ofTypeOrNull(IItem)} instead.
   *
   * @param <TYPE>
   *          the Java type to cast to
   * @param item
   *          the value to cast
   * @return the item cast to the required type or {@code null} if the item is
   *         {@code null}
   * @throws ClassCastException
   *           if the item's type is not compatible with the requested type
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @SuppressWarnings("unchecked")
  @Nullable
  public static <TYPE extends IItem> TYPE asTypeOrNull(@Nullable IItem item) {
    return (TYPE) item;
  }

  /**
   * Casts the provided {@code item} as the result type.
   * <p>
   * Use {@link IItemType#ofType(IItem)} instead.
   *
   * @param <TYPE>
   *          the Java type to cast to
   * @param item
   *          the value to cast
   * @return the item cast to the required type
   * @throws ClassCastException
   *           if the item's type is not compatible with the requested type
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @SuppressWarnings("unchecked")
  @NonNull
  public static <TYPE extends IItem> TYPE asType(@NonNull IItem item) {
    return (TYPE) item;
  }

  /**
   * Casts the provided {@code item} as the result sequence type.
   * <p>
   * Use
   * {@link ISequence#ofType(gov.nist.secauto.metaschema.core.metapath.type.IItemType)}
   * instead.
   *
   * @param <TYPE>
   *          the Java type to cast to
   * @param sequence
   *          the values to cast
   * @return the sequence cast to the required type
   * @throws ClassCastException
   *           if the sequence's type is not compatible with the requested type
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @SuppressWarnings("unchecked")
  @NonNull
  public static <TYPE extends IItem> ISequence<TYPE> asType(@NonNull ISequence<?> sequence) {
    return (ISequence<TYPE>) sequence;
  }

  /**
   * Casts the provided {@code item} as the result type.
   * <p>
   * Use {@link IItemType#test(IItem)} instead.
   *
   * @param <TYPE>
   *          the Java type to cast to
   * @param clazz
   *          the Java class instance for the requested type
   * @param item
   *          the value to cast
   * @return the item cast to the required type
   * @throws InvalidTypeMetapathException
   *           if the provided item is {@code null} or if the item's type is not
   *           assignment compatible to the requested type
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static <TYPE extends IItem> TYPE requireType(Class<TYPE> clazz, IItem item) {
    if (item == null) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("Expected non-null type '%s', but the node was null.",
              clazz.getName()));
    }
    if (!clazz.isInstance(item)) {
      throw new InvalidTypeMetapathException(
          item,
          String.format("Expected type '%s', but the node was type '%s'.",
              clazz.getName(),
              item.getClass().getName()));
    }
    return asType(item);
  }

  /**
   * Casts the provided {@code item} as the result type, if the item is not
   * {@code null}.
   * <p>
   * Use {@link IItemType#testOrNull(IItem)} instead.
   *
   * @param <TYPE>
   *          the Java type to cast to
   * @param clazz
   *          the Java class instance for the requested type
   * @param item
   *          the value to cast
   * @return the item cast to the required type or {@code null} if the item is
   *         {@code null}
   * @throws InvalidTypeMetapathException
   *           if the provided item is {@code null} or if the item's type is not
   *           assignment compatible to the requested type
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @Nullable
  public static <TYPE extends IItem> TYPE requireTypeOrNull(Class<TYPE> clazz, @Nullable IItem item) {
    if (item == null || clazz.isInstance(item)) {
      return asTypeOrNull(item);
    }
    throw new InvalidTypeMetapathException(
        item,
        String.format("Expected type '%s', but the node was type '%s'.",
            clazz.getName(),
            item.getClass().getName()));
  }

  /**
   * Get a stream of item data types for the stream of items.
   *
   * @param items
   *          the Metapath items to get the data types for
   * @return a stream of data type classes
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static Stream<Class<?>> getTypes(@NonNull Stream<? extends IItem> items) {
    return ObjectUtils.notNull(items.map(Object::getClass));
  }

  /**
   * Generate a list of Metapath item Java type classes from a list of Metapath
   * items.
   * <p>
   * Use {@link IItem#getTypes(List)} instead. Note this returns an ordered
   * collection of {@link IItemType} instances. The class can be accessed using
   * {@link IItemType#getItemClass()}.
   *
   * @param <T>
   *          the base Java types of the items
   * @param items
   *          the items to get Java type class for
   * @return a list of corresponding Java type classes for the provided items
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @SuppressWarnings("unchecked")
  @NonNull
  public static <T extends IItem> List<Class<? extends T>> getTypes(@NonNull List<T> items) {
    return ObjectUtils.notNull(items.stream()
        .map(item -> (Class<? extends T>) item.getClass())
        .collect(Collectors.toList()));
  }

  /**
   * Count the occurrences of the provided data type item {@code classes} used in
   * the set of provided {@code items}.
   *
   * @param <T>
   *          the class type
   * @param classes
   *          the Metapath item classes to count
   * @param items
   *          the Metapath items to analyze
   * @return a mapping of Metapath item class to count
   */
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static <T extends IItem> Map<Class<? extends T>, Integer> countTypes(
      @NonNull Set<Class<? extends T>> classes,
      @NonNull Collection<? extends T> items) {
    Map<Class<? extends T>, Integer> retval = new HashMap<>(); // NOPMD
    for (T item : items) {
      Class<?> itemClass = item.getClass();
      for (Class<? extends T> clazz : classes) {
        if (clazz.isAssignableFrom(itemClass)) {
          retval.compute(clazz, (cl, current) -> current == null ? 1 : current + 1);
        }
      }
    }
    return retval;
  }
}
