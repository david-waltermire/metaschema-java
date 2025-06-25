/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function;

import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItemVisitor;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.impl.AbstractMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.impl.MapItemN;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a mapping of {@link IMapKey} keys to values.
 *
 * @param <VALUE>
 *          the value type
 */
public interface IMapItem<VALUE extends ICollectionValue>
    extends IFunction, Map<IMapKey, VALUE> {
  /**
   * Get the type information for this item.
   *
   * @return the type information
   */
  @NonNull
  static IItemType type() {
    return IItemType.map();
  }

  @Override
  default IItemType getType() {
    return type();
  }

  /**
   * Get an empty, immutable map item.
   *
   * @param <V>
   *          the value Java type
   * @return an immutable map item
   */
  @NonNull
  static <V extends ICollectionValue> IMapItem<V> empty() {
    return AbstractMapItem.empty();
  }

  @Override
  Map<IMapKey, VALUE> getValue();

  @Override
  default boolean hasValue() {
    return true;
  }

  @Override
  default ISequence<?> contentsAsSequence() {
    return ISequence.of(ObjectUtils.notNull(values().stream()
        .flatMap(ICollectionValue::normalizeAsItems)));
  }

  /**
   * Determine if this sequence is empty.
   *
   * @return {@code true} if the sequence contains no items, or {@code false}
   *         otherwise
   */
  @Override
  default boolean isEmpty() {
    return getValue().isEmpty();
  }

  /**
   * Get the count of items in this sequence.
   *
   * @return the count of items
   */
  @Override
  default int size() {
    return getValue().size();

  }

  /**
   * A {@link Collector} implementation to generates a sequence from a stream of
   * Metapath items.
   *
   * @param <T>
   *          the Java type of the items
   * @return a collector that will generate a sequence
   */
  @NonNull
  static <T extends ICollectionValue> Collector<Map.Entry<IMapKey, T>, ?, IMapItem<T>> toMapItem() {
    return new Collector<Map.Entry<IMapKey, T>, Map<IMapKey, T>, IMapItem<T>>() {

      @Override
      public Supplier<Map<IMapKey, T>> supplier() {
        return LinkedHashMap::new;
      }

      @Override
      public BiConsumer<Map<IMapKey, T>, Map.Entry<IMapKey, T>> accumulator() {
        return (map, entry) -> map.putIfAbsent(entry.getKey(), entry.getValue());
      }

      @Override
      public BinaryOperator<Map<IMapKey, T>> combiner() {
        return (map1, map2) -> {
          map1.putAll(map2);
          return map1;
        };
      }

      @Override
      public Function<Map<IMapKey, T>, IMapItem<T>> finisher() {
        return map -> ofCollection(ObjectUtils.notNull(map));
      }

      @Override
      public Set<Characteristics> characteristics() {
        return Collections.emptySet();
      }
    };
  }

  @Override
  default ISequence<IMapItem<VALUE>> toSequence() {
    return ISequence.of(this);
  }

  /**
   * Get a new, immutable map item that contains the items in the provided map.
   *
   * @param <V>
   *          the value Java type
   * @param map
   *          the map whose items are to be added to the new map
   * @return a map item containing the specified entries
   */
  @NonNull
  static <V extends ICollectionValue> IMapItem<V> ofCollection(
      @NonNull Map<IMapKey, V> map) {
    return map.isEmpty() ? empty() : new MapItemN<>(map);
  }

  /**
   * Returns an unmodifiable map item containing zero mappings.
   *
   * @param <V>
   *          the value Java type
   * @return an empty {@code IMapItem}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <V extends ICollectionValue> IMapItem<V> of() {
    return AbstractMapItem.empty();
  }

  /**
   * Returns an unmodifiable map item containing a single mapping.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the mapping's key
   * @param v1
   *          the mapping's value
   * @return a map item containing the specified mapping
   * @throws NullPointerException
   *           if the key or the value is {@code null}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue> IMapItem<V> of(@NonNull K k1, @NonNull V v1) {
    return new MapItemN<>(entry(k1, v1));
  }

  /**
   * Returns an unmodifiable map item containing two mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if the keys are duplicates
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue> IMapItem<V> of(
      @NonNull K k1, @NonNull V v1,
      @NonNull K k2, @NonNull V v2) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2));
  }

  /**
   * Returns an unmodifiable map item containing three mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3));
  }

  /**
   * Returns an unmodifiable map item containing four mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3,
          @NonNull K k4, @NonNull V v4) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4));
  }

  /**
   * Returns an unmodifiable map item containing five mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3,
          @NonNull K k4, @NonNull V v4,
          @NonNull K k5, @NonNull V v5) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4),
        entry(k5, v5));
  }

  /**
   * Returns an unmodifiable map item containing six mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @param k6
   *          the sixth mapping's key
   * @param v6
   *          the sixth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings({
      "PMD.ExcessiveParameterList",
      "PMD.ShortMethodName"
  })
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3,
          @NonNull K k4, @NonNull V v4,
          @NonNull K k5, @NonNull V v5,
          @NonNull K k6, @NonNull V v6) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4),
        entry(k5, v5),
        entry(k6, v6));
  }

  // CPD-OFF
  /**
   * Returns an unmodifiable map item containing seven mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @param k6
   *          the sixth mapping's key
   * @param v6
   *          the sixth mapping's value
   * @param k7
   *          the seventh mapping's key
   * @param v7
   *          the seventh mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings({
      "PMD.ExcessiveParameterList",
      "PMD.ShortMethodName"
  })
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue> IMapItem<V> of(
      @NonNull K k1, @NonNull V v1,
      @NonNull K k2, @NonNull V v2,
      @NonNull K k3, @NonNull V v3,
      @NonNull K k4, @NonNull V v4,
      @NonNull K k5, @NonNull V v5,
      @NonNull K k6, @NonNull V v6,
      @NonNull K k7, @NonNull V v7) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4),
        entry(k5, v5),
        entry(k6, v6),
        entry(k7, v7));
  }

  /**
   * Returns an unmodifiable map item containing eight mappings. See
   * <a href="#unmodifiable">Unmodifiable Maps</a> for details.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @param k6
   *          the sixth mapping's key
   * @param v6
   *          the sixth mapping's value
   * @param k7
   *          the seventh mapping's key
   * @param v7
   *          the seventh mapping's value
   * @param k8
   *          the eighth mapping's key
   * @param v8
   *          the eighth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings({
      "PMD.ExcessiveParameterList",
      "PMD.ShortMethodName"
  })
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3,
          @NonNull K k4, @NonNull V v4,
          @NonNull K k5, @NonNull V v5,
          @NonNull K k6, @NonNull V v6,
          @NonNull K k7, @NonNull V v7,
          @NonNull K k8, @NonNull V v8) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4),
        entry(k5, v5),
        entry(k6, v6),
        entry(k7, v7),
        entry(k8, v8));
  }

  /**
   * Returns an unmodifiable map item containing nine mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @param k6
   *          the sixth mapping's key
   * @param v6
   *          the sixth mapping's value
   * @param k7
   *          the seventh mapping's key
   * @param v7
   *          the seventh mapping's value
   * @param k8
   *          the eighth mapping's key
   * @param v8
   *          the eighth mapping's value
   * @param k9
   *          the ninth mapping's key
   * @param v9
   *          the ninth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings({
      "PMD.ExcessiveParameterList",
      "PMD.ShortMethodName"
  })
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> of(
          @NonNull K k1, @NonNull V v1,
          @NonNull K k2, @NonNull V v2,
          @NonNull K k3, @NonNull V v3,
          @NonNull K k4, @NonNull V v4,
          @NonNull K k5, @NonNull V v5,
          @NonNull K k6, @NonNull V v6,
          @NonNull K k7, @NonNull V v7,
          @NonNull K k8, @NonNull V v8,
          @NonNull K k9, @NonNull V v9) {
    return new MapItemN<>(entry(k1, v1), entry(k2, v2), entry(k3, v3), entry(k4, v4), entry(k5, v5), entry(k6, v6),
        entry(k7, v7), entry(k8, v8), entry(k9, v9));
  }

  /**
   * Returns an unmodifiable map item containing ten mappings.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param k1
   *          the first mapping's key
   * @param v1
   *          the first mapping's value
   * @param k2
   *          the second mapping's key
   * @param v2
   *          the second mapping's value
   * @param k3
   *          the third mapping's key
   * @param v3
   *          the third mapping's value
   * @param k4
   *          the fourth mapping's key
   * @param v4
   *          the fourth mapping's value
   * @param k5
   *          the fifth mapping's key
   * @param v5
   *          the fifth mapping's value
   * @param k6
   *          the sixth mapping's key
   * @param v6
   *          the sixth mapping's value
   * @param k7
   *          the seventh mapping's key
   * @param v7
   *          the seventh mapping's value
   * @param k8
   *          the eighth mapping's key
   * @param v8
   *          the eighth mapping's value
   * @param k9
   *          the ninth mapping's key
   * @param v9
   *          the ninth mapping's value
   * @param k10
   *          the tenth mapping's key
   * @param v10
   *          the tenth mapping's value
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any key or value is {@code null}
   */
  @SuppressWarnings({
      "PMD.ExcessiveParameterList",
      "PMD.ShortMethodName"
  })
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue> IMapItem<V> of(
      @NonNull K k1, @NonNull V v1,
      @NonNull K k2, @NonNull V v2,
      @NonNull K k3, @NonNull V v3,
      @NonNull K k4, @NonNull V v4,
      @NonNull K k5, @NonNull V v5,
      @NonNull K k6, @NonNull V v6,
      @NonNull K k7, @NonNull V v7,
      @NonNull K k8, @NonNull V v8,
      @NonNull K k9, @NonNull V v9,
      @NonNull K k10, @NonNull V v10) {
    return new MapItemN<>(
        entry(k1, v1),
        entry(k2, v2),
        entry(k3, v3),
        entry(k4, v4),
        entry(k5, v5),
        entry(k6, v6),
        entry(k7, v7),
        entry(k8, v8),
        entry(k9, v9),
        entry(k10, v10));
    // CPD-ON
  }

  /**
   * Returns an unmodifiable map item containing keys and values extracted from
   * the given entries. The entries themselves are not stored in the map.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param entries
   *          {@code Map.Entry}s containing the keys and values from which the map
   *          is populated
   * @return a map item containing the specified mappings
   * @throws IllegalArgumentException
   *           if there are any duplicate keys
   * @throws NullPointerException
   *           if any entry, key, or value is {@code null}, or if the
   *           {@code entries} array is {@code null}
   */
  @SafeVarargs
  @SuppressWarnings("varargs")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> ofEntries(Map.Entry<IMapKey, ? extends V>... entries) {
    return entries.length == 0 ? empty() : new MapItemN<>(entries);
  }

  /**
   * Returns an unmodifiable {@link java.util.Map.Entry} containing the given key
   * and value.
   *
   * @param <V>
   *          the value's type
   * @param key
   *          the key
   * @param value
   *          the value
   * @return an {@code Map.Entry} containing the specified key and value
   * @throws NullPointerException
   *           if the key or value is {@code null}
   */
  @NonNull
  static <V extends ICollectionValue> Map.Entry<IMapKey, V> entry(@NonNull IAnyAtomicItem key, @NonNull V value) {
    return entry(key.asMapKey(), value);
  }

  /**
   * Returns an unmodifiable {@link java.util.Map.Entry} containing the given key
   * and value.
   *
   * @param <V>
   *          the value's type
   * @param key
   *          the key
   * @param value
   *          the value
   * @return an {@code Map.Entry} containing the specified key and value
   * @throws NullPointerException
   *           if the key or value is {@code null}
   */
  @SuppressWarnings("null")
  @NonNull
  static <V extends ICollectionValue> Map.Entry<IMapKey, V> entry(@NonNull IMapKey key, @NonNull V value) {
    return Map.entry(key, value);
  }

  /**
   * Returns an unmodifiable Map item containing the entries of the given Map. The
   * given Map must not be null, and it must not contain any null keys or values.
   * If the given Map is subsequently modified, the returned Map will not reflect
   * such modifications.
   *
   * @param <K>
   *          the map item's key type
   * @param <V>
   *          the map item's value type
   * @param map
   *          a map item from which entries are drawn, must be non-null
   * @return a map item containing the entries of the given {@code Map}
   * @throws NullPointerException
   *           if map is null, or if it contains any null keys or values
   */
  @SuppressWarnings("unchecked")
  @NonNull
  static <K extends IAnyAtomicItem, V extends ICollectionValue>
      IMapItem<V> copyOf(Map<? extends IMapKey, ? extends V> map) {
    return map instanceof IMapItem
        ? (IMapItem<V>) map
        : map.isEmpty()
            ? empty()
            : new MapItemN<>(new LinkedHashMap<>(map));
  }

  @Override
  default void accept(IItemVisitor visitor) {
    visitor.visit(this);
  }
}
