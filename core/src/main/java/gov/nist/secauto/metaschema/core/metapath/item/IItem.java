/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidTypeFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The base interface inherited by all Metapath item implementations.
 */
public interface IItem extends ICollectionValue {
  /**
   * Generate a list of Metapath item types classes from a list of Metapath items.
   *
   * @param <T>
   *          the item's Java type
   * @param items
   *          the items to get the type information for
   * @return a list of corresponding Metapath item type information objects in the
   *         same order as the original items
   */
  static <T extends IItem> List<IItemType> getTypes(@NonNull List<T> items) {
    return ObjectUtils.notNull(items.stream()
        .map(IItem::getType)
        .collect(Collectors.toList()));
  }

  /**
   * Get the type information for this item.
   *
   * @return the type information
   */
  @NonNull
  static IItemType type() {
    return IItemType.item();
  }

  /**
   * Get the type information for the item.
   *
   * @return the item's type information
   */
  @NonNull
  IItemType getType();

  /**
   * Get the item's "wrapped" value. This "wrapped" value may be:
   * <ul>
   * <li>In the case of an Assembly, a Java object representing the fields and
   * flags of the assembly.
   * <li>In the case of a Field with flags, a Java object representing the field
   * value and flags of the field.
   * <li>In the case of a Field without flags or a flag, a Java type managed by a
   * {@link IDataTypeAdapter} or a primitive type provided by the Java standard
   * library.
   * </ul>
   *
   * @return the value or {@code null} if the item has no available value
   */
  Object getValue();

  /**
   * Determine if the item has an associated value.
   *
   * @return {@code true} if the item has a non-{@code null} value or
   *         {@code false} otherwise
   */
  default boolean hasValue() {
    return getValue() != null;
  }

  @Override
  default ISequence<?> toSequence() {
    return ISequence.of(this);
  }

  /**
   * Get the atomic value for the item. This may be the same item if the item is
   * an instance of {@link IAnyAtomicItem}.
   * <p>
   * An implementation of
   * <a href="https://www.w3.org/TR/xpath-31/#id-atomization">item
   * atomization</a>.
   *
   * @return the atomic value or {@code null} if the item has no available value
   * @throws InvalidTypeFunctionException
   *           with code
   *           {@link InvalidTypeFunctionException#NODE_HAS_NO_TYPED_VALUE} if the
   *           item does not have a typed value
   */
  // FIXME: get rid of the possible null result and throw
  // InvalidTypeFunctionException#NODE_HAS_NO_TYPED_VALUE
  IAnyAtomicItem toAtomicItem();

  /**
   * {@inheritDoc}
   *
   * @throws InvalidTypeFunctionException
   *           with code
   *           {@link InvalidTypeFunctionException#NODE_HAS_NO_TYPED_VALUE} if the
   *           item does not have a typed value
   */
  @Override
  default Stream<IAnyAtomicItem> atomize() {
    return ObjectUtils.notNull(Stream.of(this.toAtomicItem()));
  }

  /**
   * Gets the provided item value as a {@link INumericItem} value.
   *
   * @return the numeric item value
   * @throws TypeMetapathException
   *           if the sequence contains more than one item, or the item cannot be
   *           cast to a numeric value
   */
  @NonNull
  default INumericItem toNumeric() {
    // atomize
    IAnyAtomicItem atomicItem = ISequence.getFirstItem(atomize(), true);
    if (atomicItem == null) {
      throw new InvalidTypeMetapathException(this, "Unable to cast null item");
    }
    return IDecimalItem.cast(atomicItem);
  }

  /**
   * Gets the provided item value as a {@link INumericItem} value. If the item is
   * {@code null}, then a {@code null} value is returned.
   *
   * @param item
   *          the value to convert
   * @return the numeric item value
   * @throws TypeMetapathException
   *           if the item cannot be cast to a numeric value
   */
  @Nullable
  default INumericItem toNumericOrNull() {
    // atomize
    IAnyAtomicItem atomicItem = ISequence.getFirstItem(atomize(), true);

    return atomicItem == null ? null : IDecimalItem.cast(atomicItem);
  }

  @SuppressWarnings("null")
  @Override
  default Stream<? extends IItem> flatten() {
    return Stream.of(this);
  }

  /**
   * A visitor callback used to visit a variety of Metapath item types.
   *
   * @param visitor
   *          the visitor to call back
   */
  void accept(@NonNull IItemVisitor visitor);

  @Override
  default ISequence<?> contentsAsSequence() {
    return toSequence();
  }
}
