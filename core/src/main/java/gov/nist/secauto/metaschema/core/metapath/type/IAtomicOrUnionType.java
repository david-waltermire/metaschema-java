/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.impl.NonAdapterAtomicItemType;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides type information for an atomic type.
 *
 * @param <I>
 *          the Java type of the item this type supports
 */
public interface IAtomicOrUnionType<I extends IAnyAtomicItem> extends IItemType {
  /**
   * Construct a new atomic type.
   *
   * @param <I>
   *          the Java type of the item this type supports
   * @param itemClass
   *          the Java class for the item this type supports
   * @param castExecutor
   *          the cast method used to cast other atomic types to this type
   * @param qname
   *          the qualified name of the type
   * @return the type information
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static <I extends IAnyAtomicItem> IAtomicOrUnionType<I> of(
      Class<I> itemClass,
      @NonNull ICastExecutor<I> castExecutor,
      @NonNull IEnhancedQName qname) {
    return new NonAdapterAtomicItemType<>(ObjectUtils.notNull(itemClass), castExecutor, qname);
  }

  /**
   * Get the qualified name for the type.
   *
   * @return the qualified name
   */
  @NonNull
  IEnhancedQName getQName();

  /**
   * Get the data type adapter associated with this type.
   *
   * @return the adapter or {@code null} if no adapter is associated with this
   *         type, such as the case with an abstract type
   */
  IDataTypeAdapter<?> getAdapter();

  /**
   * Get the Java class for the item this type supports.
   *
   * @return the item class
   */
  @Override
  @NonNull
  Class<I> getItemClass();

  /**
   * Check if the other type is a member of this type.
   *
   * @param other
   *          the other type to check
   * @return {@code true} if the other type is a member of this type, or
   *         {@code false} otherwise
   */
  default boolean isMemberType(@NonNull IAtomicOrUnionType<?> other) {
    // member types are not supported
    return false;
  }

  /**
   * Check if this type is the parent type of the other type.
   *
   * @param other
   *          the other type to check
   * @return {@code true} if the other type is a parent type of this type, or
   *         {@code false} otherwise
   */
  default boolean isSubType(@NonNull IAtomicOrUnionType<?> other) {
    return getItemClass().isAssignableFrom(other.getItemClass());
  }

  /**
   * Cast the provided type to this item type.
   *
   * @param item
   *          the item to cast
   * @return the original item if it is already this type, otherwise a new item
   *         cast to this type
   * @throws InvalidValueForCastFunctionException
   *           if the provided {@code item} cannot be cast to this type
   */
  @NonNull
  I cast(@NonNull IAnyAtomicItem item);

  /**
   * Cast the provided sequence to this item type.
   * <p>
   * Implements the process described in
   * <a href="https://www.w3.org/TR/xpath-31/#id-cast">XPath 3.1 Cast</a>.
   *
   * @param sequence
   *          the sequence to cast
   * @return the original item if it is already this type, otherwise a new item
   *         cast to this type
   * @throws InvalidValueForCastFunctionException
   *           if the provided {@code item} cannot be cast to this type
   * @throws TypeMetapathException
   *           if the sequence contains more than one item
   */
  @Nullable
  default I cast(@NonNull ISequence<?> sequence) {
    IAnyAtomicItem item = ISequence.of(sequence.atomize()).getFirstItem(true);
    return item == null ? null : cast(item);
  }

  /**
   * A callback used to perform a casting operation.
   *
   * @param <ITEM>
   *          the Java type for the resulting item
   */
  @FunctionalInterface
  interface ICastExecutor<ITEM extends IAnyAtomicItem> {
    /**
     * Cast the provided {@code item}.
     *
     * @param item
     *          the item to cast
     * @return the item cast to the appropriate type
     */
    @NonNull
    ITEM cast(@NonNull IAnyAtomicItem item);
  }

  /**
   * Construct a new instance of this type using the provided value.
   *
   * @param value
   *          the "wrapped" value of the type
   * @return the new item
   */
  @NonNull
  I newItem(@NonNull Object value);
}
