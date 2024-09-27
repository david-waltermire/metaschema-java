/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import java.math.BigInteger;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IPositiveIntegerItem extends INonNegativeIntegerItem {
  @SuppressWarnings("null")
  @NonNull
  IPositiveIntegerItem ONE = valueOf(BigInteger.ONE);

  /**
   * Create an item from an existing integer value.
   *
   * @param value
   *          a string representing an integer value
   * @return the item
   * @throws InvalidTypeMetapathException
   *           if the provided value is not a positive integer
   */
  @NonNull
  static IPositiveIntegerItem valueOf(@NonNull String value) {
    try {
      return valueOf(new BigInteger(value));
    } catch (NumberFormatException ex) {
      throw new InvalidTypeMetapathException(null,
          ex.getMessage(),
          ex);
    }
  }

  /**
   * Create an item from an existing integer value.
   *
   * @param value
   *          an integer value
   * @return the item
   * @throws InvalidTypeMetapathException
   *           if the provided value is not a positive integer
   */
  @NonNull
  static IPositiveIntegerItem valueOf(@NonNull IIntegerItem value) {
    return valueOf(value.asInteger());
  }

  /**
   * Create an item from an existing integer value.
   *
   * @param value
   *          an integer value
   * @return the item
   * @throws InvalidTypeMetapathException
   *           if the provided value is not a positive integer
   */
  @SuppressWarnings("null")
  @NonNull
  static IPositiveIntegerItem valueOf(long value) {
    return valueOf(BigInteger.valueOf(value));
  }

  /**
   * Create an item from an existing integer value.
   *
   * @param value
   *          an integer value
   * @return the item
   * @throws InvalidTypeMetapathException
   *           if the provided value is not a positive integer
   */
  @NonNull
  static IPositiveIntegerItem valueOf(@NonNull BigInteger value) {
    if (value.compareTo(BigInteger.ZERO) <= 0) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("Integer value '%s' is negative or zero.", value));
    }
    return new PositiveIntegerItemImpl(value);
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
  static IPositiveIntegerItem cast(@NonNull IAnyAtomicItem item) {
    return MetaschemaDataTypeProvider.POSITIVE_INTEGER.cast(item);
  }

  @Override
  default IPositiveIntegerItem castAsType(IAnyAtomicItem item) {
    return valueOf(cast(item).asInteger());
  }
}
