/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;

import java.util.UUID;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IUuidItem extends IStringItem {

  /**
   * Construct a new item using the provided {@code value}.
   *
   * @param value
   *          a UUID value
   * @return the new item
   */
  @NonNull
  static IUuidItem valueOf(@NonNull UUID value) {
    return new UuidItemImpl(value);
  }

  /**
   * Generate a random UUID value.
   *
   * @return the generated UUID item
   */
  @SuppressWarnings("null")
  @NonNull
  static IUuidItem random() {
    return valueOf(UUID.randomUUID());
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
  static IUuidItem cast(@NonNull IAnyAtomicItem item) {
    return MetaschemaDataTypeProvider.UUID.cast(item);
  }

  /**
   * Get the "wrapped" UUID value.
   *
   * @return the underlying UUID value
   */
  @NonNull
  UUID asUuid();

  @Override
  default IUuidItem castAsType(IAnyAtomicItem item) {
    return cast(item);
  }

  /**
   * Compares this value with the argument.
   *
   * @param item
   *          the item to compare with this value
   * @return a negative integer, zero, or a positive integer if this value is less
   *         than, equal to, or greater than the {@code item}.
   */
  default int compareTo(@NonNull IUuidItem item) {
    return asUuid().compareTo(item.asUuid());
  }

  @Override
  default int compareTo(IAnyAtomicItem other) {
    return compareTo(other.asStringItem());
  }
}
